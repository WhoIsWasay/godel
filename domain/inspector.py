import hashlib
import json
import re
from difflib import SequenceMatcher
from langchain_core.messages import HumanMessage, SystemMessage


class Inspector:

    def __init__(self, isolator_llm, compositor_llm):
        with open("prompts/isolator.txt", "r", encoding="utf-8") as f:
            self.isolator_prompt = f.read()

        with open("prompts/compositor.txt", "r", encoding="utf-8") as f:
            self.compositor_prompt = f.read()

        self.isolator_agent = isolator_llm
        self.compositor_agent = compositor_llm

    def _invoke(self, agent, system_prompt: str, user_input: str) -> str:
        response = agent.invoke(
            [
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_input),
            ]
        )
        return response.content.strip()

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
            all_isolated.extend(result["findings"])
            print(f"   Run {i+1}: {len(result['findings'])} findings")

        # Now leveraging the line intersection + Jaccard overlap deduplicator
        isolated_deduped = self.deduplicate(all_isolated)
        print(f"Isolator deduplicated: {len(isolated_deduped)} unique findings")

        # Pass 2 — Compositor x1
        print("=== INSPECTOR COMPOSITOR ===")

        # Slim findings for Compositor — only essential fields
        slim_findings = [
            {
                "id": f["id"],
                "intent": f["intent"],
                "target_function": f["target_function"],
                "class": f["class"],
            }
            for f in isolated_deduped
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

                    intent_sim = self._word_overlap_ratio(
                        finding.get("intent", ""), existing.get("intent", "")
                    )

                    # TRIGGER: Matches the same code execution point AND contains highly similar intent
                    if (
                        has_code_overlap
                        and intent_sim > intent_similarity_threshold
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

        Handles markdown blocks and repairs truncated or malformed JSON payloads
        defensively.
        """
        json_str = raw_response.strip()
        if "```json" in json_str:
            json_str = json_str.split("```json")[1].split("```")[0].strip()
        elif "```" in json_str:
            json_str = json_str.split("```")[1].split("```")[0].strip()

        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            print(
                "      [WARNING] Malformed or truncated JSON detected. Executing auto-repair pass..."
            )
            return self._repair_truncated_json(json_str)

    def _repair_truncated_json(self, json_str: str) -> dict:
        """Defensively patches open quotes and balances trailing structural braces

        for broken or truncated LLM JSON payloads.
        """
        json_str = json_str.strip()

        # Issue 1: Fix unclosed strings/quotes
        quotes = len(re.findall(r'(?<!\\)"', json_str))
        if quotes % 2 != 0:
            json_str += '"'

        # Issue 2: Balance brackets and braces
        open_braces = json_str.count("{")
        close_braces = json_str.count("}")
        open_brackets = json_str.count("[")
        close_brackets = json_str.count("]")

        if (
            open_brackets > close_brackets
            and not json_str.endswith("}")
            and open_braces > close_braces
        ):
            json_str += "}"
            close_braces += 1

        if open_brackets > close_brackets:
            json_str += "]" * (open_brackets - close_brackets)

        if open_braces > close_braces:
            json_str += "}" * (open_braces - close_braces)

        try:
            return json.loads(json_str)
        except Exception as e:
            print(
                f"      [CRITICAL] Auto-repair failed. Returning empty findings list. Error: {e}"
            )
            return {"findings": []}