import hashlib
import json
import re
from difflib import SequenceMatcher
from langchain_core.messages import HumanMessage, SystemMessage

from domain import config
from domain.config import PROMPTS_DIR
from domain.llm_utils import (EmptyResponseError, call_with_retry,
                              content_to_text, guarded_invoke)


class Inspector:

    def __init__(self, isolator_llm, compositor_llm):
        with open(PROMPTS_DIR / "isolator.txt", "r", encoding="utf-8") as f:
            self.isolator_prompt = f.read()

        with open(PROMPTS_DIR / "compositor.txt", "r", encoding="utf-8") as f:
            self.compositor_prompt = f.read()

        self.isolator_agent = isolator_llm
        self.compositor_agent = compositor_llm

    def _invoke(self, agent, system_prompt: str, user_input: str) -> str:
        def _call():
            response = guarded_invoke(
                agent,
                [
                    SystemMessage(content=system_prompt),
                    HumanMessage(content=user_input),
                ],
            )
            content = content_to_text(response.content).strip()
            if not content:
                # An HTTP-200 with no content is a transient provider fault,
                # NOT a real "no findings" answer. Retry it.
                raise EmptyResponseError(
                    "LLM returned empty content — treating as transient provider fault"
                )
            return content

        return call_with_retry(_call)

    def run(self, xml_code: str, readme: str = "") -> dict:
        # Pass 1 — Isolator x3
        print("=== INSPECTOR ISOLATOR (3x runs) ===")
        isolator_input = f"{readme}\n\n{xml_code}" if readme else xml_code

        input_hash = hashlib.md5(isolator_input.encode()).hexdigest()
        print(f"Input hash: {input_hash}")
        print(f"Input length: {len(isolator_input)} chars")

        all_isolated = []
        for i in range(3):
            raw = self._invoke(
                self.isolator_agent, self.isolator_prompt, isolator_input
            )
            result = self.extract_json(raw)
            findings = result.get("findings") or []
            all_isolated.extend(f for f in findings if isinstance(f, dict))
            print(f"   Run {i+1}: {len(findings)} findings")

        # Now leveraging the line intersection + Jaccard overlap deduplicator
        isolated_deduped = self.deduplicate(all_isolated)
        print(f"Isolator deduplicated: {len(isolated_deduped)} unique findings")

        # Pass 2 — Compositor x1
        print("=== INSPECTOR COMPOSITOR ===")

        # Slim findings for Compositor — only essential fields
        slim_findings = [
            {
                "id": f.get("id", idx),
                "intent": f.get("intent", ""),
                "target_function": f.get("target_function", ""),
                "class": f.get("class", "isolated"),
            }
            for idx, f in enumerate(isolated_deduped, 1)
        ]

        compositor_input = f"""{readme}

{xml_code}

<isolated_findings>
{json.dumps(slim_findings, indent=2)}
</isolated_findings>"""

        compositor_raw = self._invoke(
            self.compositor_agent, self.compositor_prompt, compositor_input
        )
        compositor_findings = self.extract_json(compositor_raw)
        print(f"Compositor found: {len(compositor_findings['findings'])} findings")

        # Merge
        merged = self.merge(
            {"findings": isolated_deduped}, compositor_findings
        )
        print(f"Total findings: {merged['total_findings']}")
        return merged

    def _word_overlap_ratio(self, a: str, b: str) -> float:
        """Jaccard similarity on significant words (4+ chars), ignoring sentence

        structure and word order to cleanly survive heavy LLM paraphrasing.
        """

        def words(s):
            return set(w.lower() for w in re.findall(r"\b\w{4,}\b", s))

        wa, wb = words(a), words(b)
        if not wa or not wb:
            return 0.0
        return len(wa & wb) / len(wa | wb)

    def deduplicate(
        self, findings: list, intent_similarity_threshold: float = 0.4
    ) -> list:
        grouped = {}
        for f in findings:
            key = f.get("target_function", "").strip()
            grouped.setdefault(key, []).append(f)

        result = []

        def get_significant_lines(code_str):
            """Breaks code into a set of normalized, clean lines to remove spacing variations."""
            lines = code_str.split("\n")
            clean_lines = set()
            for line in lines:
                # Strip comments, ellipsis, and structural tokens like braces/semicolons
                clean = re.sub(r"//.*|/\*.*\*/|\.\.\.", "", line).strip()
                clean = re.sub(r"[{};() ]", "", clean)
                if (
                    len(clean) > 3
                ):  # Only care about lines with meaningful code tokens
                    clean_lines.add(clean)
            return clean_lines

        for func_name, group in grouped.items():
            kept = []
            for finding in group:
                is_dup = False
                finding_code_lines = get_significant_lines(
                    finding.get("relevant_code", "")
                )

                for existing in kept:
                    existing_code_lines = get_significant_lines(
                        existing.get("relevant_code", "")
                    )

                    # Overlap metric: Do they share at least one core line of logic?
                    # If either is empty, default to True to let the intent text decide.
                    has_code_overlap = (
                        bool(finding_code_lines & existing_code_lines)
                        if (finding_code_lines and existing_code_lines)
                        else True
                    )

                    strong_code_overlap = False
                    if finding_code_lines and existing_code_lines:
                        intersection = finding_code_lines & existing_code_lines
                        smaller = min(len(finding_code_lines), len(existing_code_lines))
                        if smaller > 0 and len(intersection) >= smaller:
                            strong_code_overlap = True

                    intent_sim = self._word_overlap_ratio(
                        finding.get("intent", ""), existing.get("intent", "")
                    )

                    constraint_sim = self._word_overlap_ratio(
                        finding.get("constraint", ""), existing.get("constraint", "")
                    )

                    threshold = intent_similarity_threshold
                    if strong_code_overlap:
                        threshold = 0.15

                    if has_code_overlap and (
                        intent_sim > threshold or constraint_sim > 0.5
                    ):
                        is_dup = True
                        break

                if not is_dup:
                    kept.append(finding)
            result.extend(kept)

        for i, f in enumerate(result, start=1):
            f["id"] = i
        return result

    def extract_json(self, raw_response: str) -> dict:
        """Extracts JSON from an LLM response string.

        Delegates to domain.json_extract: string-aware fence/brace
        extraction plus content-preserving truncation repair. Always
        returns a dict — a bare JSON list is wrapped as the findings
        array, and unparseable output degrades to an empty findings list
        (callers treat empty-after-failed-parse as a parse failure, never
        as a clean result).
        """
        from domain.json_extract import extract_json_value

        value, err = extract_json_value(raw_response)
        if isinstance(value, list):
            return {"findings": value}
        if isinstance(value, dict):
            return value
        print(f"      [CRITICAL] No recoverable JSON in LLM output ({err}). "
              f"Returning empty findings list.")
        return {"findings": []}