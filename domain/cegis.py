"""domain/cegis.py — Phase 2: real counterexample-guided repair loop.

Previously an empty shell: the CEGIS prompt loaded but nothing used it. Now:

  run_with_repair(z3_code)
      1. Executes the script via the injected run_z3 tool.
      2. On execution ERROR, feeds the exact error + script to the LLM
         (prompts/cegis_prompt.txt) for a bounded number of repairs and re-runs.
      3. On SAT, extracts concrete counterexample assignments from the output
         so downstream nodes (gatekeeper PoC generation, bug_report) get
         attacker-controlled values instead of prose.

Bounded by `max_repairs` (default 2) — the graph's own EXECUTOR_MAX_ITERATIONS
loop still bounds total refinement cycles above this layer.
"""

import logging
import re

from langchain_core.messages import SystemMessage, HumanMessage

from domain import config
from domain.llm_utils import call_with_retry, guarded_invoke

logger = logging.getLogger(__name__)

_CEX_PAIR_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_$.]*)\s*[:=]\s*(-?\d+)")


class CEGIS:
    with open(config.PROMPTS_DIR / "cegis_prompt.txt", "r", encoding="utf-8") as _f:
        SYSTEM_PROMPT = _f.read()

    def __init__(self, agent, run_z3_tool):
        self.agent = agent
        self.run_z3 = run_z3_tool

    # ------------------------------------------------------------- main API
    def run_with_repair(self, z3_code: str, max_repairs: int = None) -> dict:
        if max_repairs is None:
            max_repairs = max(1, config.EXECUTOR_MAX_ITERATIONS // 2)

        result = self.run_z3(z3_code)
        repairs = 0
        while result.get("status") == "error" and repairs < max_repairs:
            print(f"      [CEGIS] Z3 error — guided repair attempt "
                  f"{repairs + 1}/{max_repairs}")
            fixed = self._repair_script(z3_code, result.get("error") or "")
            if not fixed:
                logger.warning("[CEGIS] repair LLM returned no usable code")
                break
            z3_code = fixed
            result = self.run_z3(z3_code)
            repairs += 1

        result["repairs_used"] = repairs
        if result.get("status") == "sat":
            result["counterexample"] = self.extract_counterexample(
                result.get("output") or "")
        else:
            result["counterexample"] = None
        return result

    # ------------------------------------------------------------ internals
    def _repair_script(self, z3_code: str, error: str) -> str | None:
        """Asks the LLM to fix the failing Z3 script. Returns corrected code or None."""
        from langchain_core.messages import SystemMessage, HumanMessage

        user = f"""=== FAILING Z3 CODE ===
{z3_code}

=== EXECUTION ERROR ===
{error[:4000]}

Return ONLY the corrected full Python code block."""
        try:
            response = call_with_retry(lambda: guarded_invoke(self.agent, [
                SystemMessage(content=self.SYSTEM_PROMPT),
                HumanMessage(content=user),
            ]))
        except Exception as e:
            logger.error("[CEGIS] repair invoke failed: %s", e)
            return None

        raw = response.content.strip()
        raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
        if "```python" in raw:
            return raw.split("```python")[1].split("```")[0].strip()
        if "```" in raw:
            parts = raw.split("```")
            return parts[-2].strip() if len(parts) >= 3 else raw.strip()
        if "from z3 import" in raw or "build_model" in raw:
            return raw
        return None

    @staticmethod
    def extract_counterexample(sat_output: str) -> dict:
        """Parses 'BUG FOUND:' payloads into structured assignments.

        Understands both raw solver.model() dumps and key=value lines; falls
        back to a truncated raw string when nothing structured is found."""
        body = sat_output.split("BUG FOUND:", 1)[1] if "BUG FOUND:" in sat_output else sat_output
        pairs = {k: int(v) for k, v in _CEX_PAIR_RE.findall(body)}
        cex = {"assignments": pairs}
        if not pairs:
            cex["raw"] = body.strip()[:400]
        else:
            cex["raw"] = " ".join(body.split())[:400]
        return cex
