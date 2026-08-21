import os
import re
import logging
from string import Template
from langchain_openai import ChatOpenAI

logger = logging.getLogger(__name__)


class FixerAgent:

    _PROMPT_PATH = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "prompts", "fixer_prompt.txt" #HERE
    )

    def __init__(self, agent: ChatOpenAI):
        """
        Initializes the Fixer Agent with the high-reasoning LLM client (llm_pro).
        """
        self.agent = agent
        self.prompt_template = self._load_prompt_template()

    def _load_prompt_template(self) -> str:
        """
        Loads the prompt template from disk. Returns an empty string (rather than
        raising) if the file is missing or unreadable, so the agent can fall back
        to placeholder output instead of crashing at construction time.
        """
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
        """
        Sends the bug context and solver proof details to the high-reasoning model.
        Returns a clean, refactored version of the target function block.
        """
        # Assemble context strings from the pipeline state
        target_function_name = finding.get("target_function", "unknown")
        bug_intent = finding.get("intent", "No intent specified.")
        invariant_constraint = finding.get("constraint", "No constraint specified.")
        vulnerable_code_block = finding.get("relevant_code", "")
        solver_trace_log = state.get("bug_report", "No trace generated.")
        full_contract = state.get("user_contract", "")

        # If the template is empty, output a fallback string until we build the prompt
        if not self.prompt_template:
            return f"// Concrete fix placeholder for {target_function_name} (Prompt template not yet implemented)"

        # Formatting execution payload.
        # Template.safe_substitute is used instead of str.format(): the prompt
        # template will keep growing (schema examples, sample code blocks, etc.)
        # and Solidity/JSON snippets are full of literal { } characters. format()
        # requires every one of those to be manually escaped as {{ }} or it throws
        # KeyError; Template uses $placeholder syntax so literal braces in the
        # template need no escaping at all. safe_substitute (vs substitute) also
        # means a typo'd or missing $placeholder in the template won't crash this
        # call — it just leaves that token unsubstituted, which is easier to spot
        # and debug than a hard KeyError mid-pipeline.
        try:
            formatted_prompt = Template(self.prompt_template).safe_substitute(
                function_name=target_function_name,
                intent=bug_intent,
                constraint=invariant_constraint,
                vulnerable_code=vulnerable_code_block,
                solver_trace=solver_trace_log,
                full_contract_context=full_contract,
            )
        except Exception as e:
            return f"// Error formatting Fixer prompt for function {target_function_name}: {str(e)}"

        try:
            # Invoke deepseek-v4-pro with thinking tokens enabled
            response = self.agent.invoke(formatted_prompt)
            raw_content = response.content

            # Clean and isolate the code block if the LLM wraps it in markdown triple backticks
            cleaned_code = self._extract_clean_solidity(raw_content)
            return cleaned_code

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