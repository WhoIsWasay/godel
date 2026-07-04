
from langchain_core.messages import SystemMessage, HumanMessage
import json
import re
import hashlib


class Inspector:

    def __init__(self, isolator_llm, compositor_llm):
        with open("prompts/isolator.txt", "r", encoding="utf-8") as f:
            self.isolator_prompt = f.read()

        with open("prompts/compositor.txt", "r", encoding="utf-8") as f:
            self.compositor_prompt = f.read()

        self.isolator_agent = isolator_llm
        self.compositor_agent = compositor_llm

    def _invoke(self, agent, system_prompt: str, user_input: str) -> str:
        response = agent.invoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_input),
        ])
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
            raw = self._invoke(self.isolator_agent, self.isolator_prompt, isolator_input)
            result = self.extract_json(raw)
            all_isolated.extend(result["findings"])
            print(f"  Run {i+1}: {len(result['findings'])} findings")

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
                "class": f["class"]
            }
            for f in isolated_deduped
        ]

        compositor_input = f"""{readme}

{xml_code}

<isolated_findings>
{json.dumps(slim_findings, indent=2)}
</isolated_findings>"""

        compositor_raw = self._invoke(
            self.compositor_agent,
            self.compositor_prompt,
            compositor_input
        )
        compositor_findings = self.extract_json(compositor_raw)
        print(f"Compositor found: {len(compositor_findings['findings'])} findings")

        # Merge
        merged = self.merge({"findings": isolated_deduped}, compositor_findings)
        print(f"Total findings: {merged['total_findings']}")
        return merged

    def deduplicate(self, findings: list) -> list:
        seen = {}
        result = []

        for f in findings:
            # Primary key: same function + same tool + same class
            primary_key = (
                f.get("target_function", "").strip(),
                f.get("tool_hint", ""),
                f.get("class", "")
            )

            # Secondary key: same function + same severity + same class
            # catches same bug described with different tool hint
            secondary_key = (
                f.get("target_function", "").strip(),
                f.get("severity_guess", ""),
                f.get("class", "")
            )

            if primary_key not in seen and secondary_key not in seen:
                seen[primary_key] = True
                seen[secondary_key] = True
                result.append(f)

        for i, f in enumerate(result, start=1):
            f["id"] = i

        return result

    def merge(self, isolated: dict, compositional: dict) -> dict:
        all_findings = []

        for f in isolated["findings"]:
            all_findings.append(f)

        for f in compositional["findings"]:
            all_findings.append(f)

        # Renumber sequentially
        id_map = {}
        for i, f in enumerate(all_findings, start=1):
            id_map[f["id"]] = i
            f["id"] = i

        # Fix related_to after renumbering
        for f in all_findings:
            if f.get("related_to"):
                f["related_to"] = [
                    id_map.get(ref, ref)
                    for ref in f["related_to"]
                ]

        return {
            "total_findings": len(all_findings),
            "findings": all_findings
        }

    def extract_json(self, raw_response: str) -> dict:
        """
        Extracts JSON from an LLM response string. Handles markdown blocks
        and repairs truncated or malformed JSON payloads defensively.
        """
        # 1. Strip out markdown code fences if they exist
        json_str = raw_response.strip()
        if "```json" in json_str:
            json_str = json_str.split("```json")[1].split("```")[0].strip()
        elif "```" in json_str:
            json_str = json_str.split("```")[1].split("```")[0].strip()

        # 2. Try an absolute normal load pass
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            # If normal loading fails, trigger the defensive repair engine
            print("      [WARNING] Malformed or truncated JSON detected. Executing auto-repair pass...")
            return self._repair_truncated_json(json_str)

    def _repair_truncated_json(self, json_str: str) -> dict:
        """
        Defensively patches open quotes and balances trailing structural braces 
        for broken or truncated LLM JSON payloads.
        """
        json_str = json_str.strip()
        
        # Issue 1: Fix unclosed strings/quotes
        # Count open unescaped quotes
        quotes = len(re.findall(r'(?<!\\)"', json_str))
        if quotes % 2 != 0:
            # If odd, the last quote block was never closed. Seal it.
            json_str += '"'

        # Issue 2: Balance brackets and braces
        # Count structural tokens to track nesting depth
        open_braces = json_str.count("{")
        close_braces = json_str.count("}")
        open_brackets = json_str.count("[")
        close_brackets = json_str.count("]")

        # Check if a dictionary or array item was cut off right after a key or value
        if open_brackets > close_brackets and not json_str.endswith("}") and open_braces > close_braces:
            json_str += "}"
            close_braces += 1

        # Close dangling array sequences
        if open_brackets > close_brackets:
            json_str += "]" * (open_brackets - close_brackets)
            
        # Close dangling root object envelopes
        if open_braces > close_braces:
            json_str += "}" * (open_braces - close_braces)

        # Try loading the newly repaired variant
        try:
            return json.loads(json_str)
        except Exception as e:
            print(f"      [CRITICAL] Auto-repair failed. Returning empty findings list. Error: {e}")
            return {"findings": []}