import json
from langchain_core.messages import SystemMessage, HumanMessage

from domain.config import PROMPTS_DIR
from domain.llm_utils import call_with_retry


class PropertyGenerator:

    with open(PROMPTS_DIR / "property_generator_prompt.txt", "r", encoding="utf-8") as f:
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
        response = call_with_retry(
            lambda: self.agent.invoke([
                SystemMessage(content=self.SYSTEM_PROMPT),
                HumanMessage(content=self.prompt),
            ])
        )
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



    def build_prompt(self, expansion: dict, contract: str, findings: list[dict],
                     semantic_harness: dict | None = None,
                     repair_feedback: str | None = None) -> None:
        intent = expansion["intent"]
        queries = expansion["queries"]
        formatted_queries = "\n".join(f"- {q}" for q in queries)
        formatted_findings = self.format_findings(findings)

        if semantic_harness:
            from domain.semantics import PROPERTY_PROTOCOL_COMMENT
            harness_section = f"""
        === DETERMINISTIC SEMANTIC MODEL (authoritative — generated from static analysis) ===
        ```python
        {semantic_harness['code']}
        ```
        Model quality: {semantic_harness['quality']}.
        Unmodeled (havocked, i.e. free) parts: {json.dumps(semantic_harness['untranslated'], indent=2)}
        Standing assumptions: {json.dumps(semantic_harness['assumptions'])}

        {PROPERTY_PROTOCOL_COMMENT}
        You MUST use build_model() and the V[...] symbols. Do NOT re-declare state
        variables or invent semantics that contradict the model.
        """
        else:
            harness_section = """
        No deterministic model is available for this function: encode the Solidity
        semantics yourself with Z3 as before. Be conservative: anything you cannot
        faithfully encode must remain a free/unconstrained variable.
        """

        repair_section = ""
        if repair_feedback:
            repair_section = f"""
<repair_feedback>
{repair_feedback}
</repair_feedback>
Your PREVIOUS Z3 script was rejected for the reason above. Diagnose it first,
then generate a corrected script that addresses exactly that failure while
keeping the property faithful to the contract code."""

        self.prompt = f"""<intent>
{intent}

=== EXPANDED QUERIES ===
{formatted_queries}
</intent>

<contract>
{contract}
</contract>

<findings>
{formatted_findings}
</findings>
{harness_section}{repair_section}
=== TASK ===
Generate Z3 Python code that encodes and tests the above verification intent.
Use the exact variable names from the contract. Encode edge cases derived from the findings.
Output only the Python code block. No explanation. No prose. No markdown fences."""





