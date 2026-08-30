import os
import re
import logging
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_openai import ChatOpenAI

from domain.llm_utils import call_with_retry, guarded_invoke

logger = logging.getLogger(__name__)


class FixerAgent:

    _PROMPT_PATH = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "prompts", "fixer_prompt.txt"
    )

    def __init__(self, agent: ChatOpenAI):
        self.agent = agent
        self.system_prompt = self._load_system_prompt()

    def _load_system_prompt(self) -> str:
        try:
            with open(self._PROMPT_PATH, "r", encoding="utf-8") as f:
                content = f.read()
            if not content.strip():
                logger.warning("[FixerAgent] prompt template at %s is empty.", self._PROMPT_PATH)
            return content
        except FileNotFoundError:
            logger.warning("[FixerAgent] prompt template not found at %s.", self._PROMPT_PATH)
            return ""
        except OSError as e:
            logger.warning("[FixerAgent] could not read prompt template (%s).", e)
            return ""

    def generate_remediation(self, finding: dict, state: dict) -> str:
        target_function_name = finding.get("target_function", "unknown")
        bug_intent = finding.get("intent", "No intent specified.")
        invariant_constraint = finding.get("constraint", "No constraint specified.")
        vulnerable_code_block = finding.get("relevant_code", "")
        solver_trace_log = state.get("bug_report", "") or ""
        full_contract = state.get("user_contract", "")

        if not self.system_prompt:
            return f"// Concrete fix placeholder for {target_function_name} (Prompt template not yet implemented)"

        user_payload = f"""<full_contract_context>
{full_contract}
</full_contract_context>

<vulnerable_code_boundary>
{vulnerable_code_block}
</vulnerable_code_boundary>

<solver_counterexample_trace>
{solver_trace_log}
</solver_counterexample_trace>

<finding_metadata>
<function_name>{target_function_name}</function_name>
<intent>{bug_intent}</intent>
<invariant_constraint>{invariant_constraint}</invariant_constraint>
</finding_metadata>

Output the corrected `{target_function_name}` function body only, inside ```solidity fences."""

        try:
            response = call_with_retry(
                lambda: guarded_invoke(self.agent, [
                    SystemMessage(content=self.system_prompt),
                    HumanMessage(content=user_payload),
                ])
            )
            return self._extract_clean_solidity(response.content)
        except Exception as e:
            return f"// Error executing Fixer Agent logic for function {target_function_name}: {str(e)}"

    def _extract_clean_solidity(self, text: str) -> str:
        """
        Helper method to strip markdown formatting blocks (```solidity ... ```)
        and isolate pure, compilable code text.
        """
        pattern = r"```solidity(.*?)```"
        match = re.search(pattern, text, re.DOTALL)
        if match:
            return match.group(1).strip()

        # Secondary fallback pattern if it just uses general code fences
        pattern_generic = r"```(.*?)```"
        match_generic = re.search(pattern_generic, text, re.DOTALL)
        if match_generic:
            return match_generic.group(1).strip()

        return text.strip()