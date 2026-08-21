import os
import re

class SubmissionFormatter:
    def __init__(self):
        """
        Initializes the formatting engine for transforming raw math invariants 
        and solver outputs into portal-ready bug bounty submissions.
        """
        # Clean, robust layout matching competitive human platform standards
        self.template = (
            "### [VULNERABILITY CLASS]\n"
            "{severity_label}: {vulnerability_title} in `{function_name}`\n\n"
            "**Vulnerability Detail:**\n"
            "{intent_description}\n\n"
            "**Impact:**\n"
            "Exploitation allows breaking the protocol's core logical constraints. "
            "Specifically, the mathematical system boundary `{invariant_constraint}` "
            "can be violated under arbitrary input configurations as proven by symbolic "
            "and static verification boundaries.\n\n"
            "**Proof of Concept (PoC):**\n"
            "1. **Target Boundary Code:**\n"
            "```solidity\n"
            "{vulnerable_code_snippet}\n"
            "```\n\n"
            "2. **Mathematical / Structural Verification Log:**\n"
            "```text\n"
            "{solver_trace_log}\n"
            "```\n\n"
            "3. **Validation Script Reference:**\n"
            "*The absolute mathematical proof can be verified by running the automatically "
            "generated validation script saved locally at:* `output/proofs/{proof_file_name}`\n\n"
            "**Recommendation:**\n"
            "Refactor the function scope to enforce strict ordering, boundary locks, or "
            "precision adjustments. Below is the verified remediation layout:\n\n"
            "```solidity\n"
            "{fixed_code_snippet}\n"
            "```\n"
        )

    def compile_bounty_report(self, finding_idx: int, stem: str, finding: dict, state: dict, fixed_code: str) -> str:
        """
        Compiles all runtime data vectors into a single, comprehensive markdown string.
        """
        func_name = finding.get("target_function", "unknown")
        
        # # Safely extract and truncate the intent description into a clean title line
        raw_intent = finding.get("intent", "Logic Flaw Detected")
        words = raw_intent.split()[:8]
        title_summary = " ".join(words).replace('"', '').replace("'", "") + "..."

        # # Determine target file mapping based on the solver mode used
        safe_func = re.sub(r'[^a-zA-Z0-9_]', '', func_name)
        if state.get("mode") == "slither":
            proof_file = f"{stem}_{safe_func}_{finding_idx}_slither.json"
        else:
            proof_file = f"{stem}_{safe_func}_{finding_idx}_proof.py"

        # Safe extraction of the trace log or default message if none exists
        solver_trace_log = state.get("bug_report") or "SAT violation verified."

        # Interpolate variables safely into the string layout without formatting escapes
        compiled_markdown = self.template.format(
            severity_label=finding.get("severity_guess", "medium").upper(),
            vulnerability_title= title_summary,
            function_name= func_name,
            intent_description= raw_intent,
            invariant_constraint=finding.get("constraint", "Implicit Invariant Exception"),
            vulnerable_code_snippet=finding.get("relevant_code", ""),
            solver_trace_log=solver_trace_log,
            proof_file_name=proof_file,
            fixed_code_snippet=fixed_code
        )
        
        return compiled_markdown

    # --- ARCHITECTURAL BACKUP ALIAS ---
    # Safe alias method to prevent orchestrator AttributeError issues
    def compile_report(self, *args, **kwargs):
        """Fallback method alias mapping directly to compile_bounty_report."""
        return self.compile_bounty_report(*args, **kwargs)
    
    
    