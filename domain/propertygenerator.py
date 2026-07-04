import json
from langchain_core.messages import SystemMessage, HumanMessage


class PropertyGenerator:

    with open("prompts/property_generator_prompt.txt", "r") as f:
        SYSTEM_PROMPT = f.read()

    def __init__(self, agent):
        self.agent = agent

    def format_findings(self,findings: list[dict]) -> str:
        lines = []
        for i, f in enumerate(findings, 1):
            lines.append(f"[{i}] Title: {f['title_normalized']}")
            lines.append(f"    Vuln Class: {f['vuln_class']} | Severity: {f['severity']}")
            lines.append(f"    Description: {f['description'][:400].strip()}...")
            if f.get('code_snippet'):
                lines.append(f"    Code: {f['code_snippet'][:200].strip()}")
                lines.append("")
        return "\n".join(lines)
    
    
    
    def propertyGeneration(self) -> str:
        response = self.agent.invoke([
        SystemMessage(content=self.SYSTEM_PROMPT),
        HumanMessage(content=self.prompt),
    ])
        raw = response.content

        if "```python" in raw:
            code = raw.split("```python")[1].split("```")[0].strip()
        elif "```" in raw:
        # fence present but no language tag — take the last fenced block
        # (scratchpad, if fenced, would be the first; code should be the last)
            parts = raw.split("```")
            code = parts[-2].strip() if len(parts) >= 3 else raw.strip()
        elif "from z3 import *" in raw:
        # no fence at all — fall back to slicing from the known code start marker
            code = "from z3 import *" + raw.split("from z3 import *", 1)[1]
        else:
            code = raw.strip()

        return code

    def propertyGeneration(self) -> str:
        response = self.agent.invoke([
        SystemMessage(content=self.SYSTEM_PROMPT),  # your system prompt constant
        HumanMessage(content=self.prompt),
    ])
        raw = response.content
    # strip markdown fences if present
        if "```python" in raw:
            raw = raw.split("```python")[1].split("```")[0].strip()
        return raw


    def build_prompt(self, expansion: dict, contract: str, findings: list[dict]) -> None:
        intent = expansion["intent"]
        queries = expansion["queries"]
        formatted_queries = "\n".join(f"- {q}" for q in queries)
        formatted_findings = self.format_findings(findings)

        self.prompt = f"""=== VERIFICATION INTENT ===
        {intent}

        === EXPANDED QUERIES ===
        {formatted_queries}

        === CONTRACT ===
        {contract}

        === HISTORICAL FINDINGS ===
        {formatted_findings}

        === TASK ===
        Generate Z3 Python code that encodes and tests the above verification intent.
        Use the exact variable names from the contract. Encode edge cases derived from the findings.
        Output only the Python code block. No explanation. No prose. No markdown fences."""





