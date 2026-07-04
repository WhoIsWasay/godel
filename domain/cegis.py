import json
from langchain_core.messages import SystemMessage, HumanMessage
from domain.state import GraphState

class CEGIS:
    with open("prompts/cegis_prompt.txt", "r") as f:
        SYSTEM_PROMPT = f.read()

    def __init__(self, agent, run_z3_tool):
        self.agent = agent
        self.run_z3 = run_z3_tool

    def cegis_loop(self, state: GraphState) -> GraphState:
        iterations = 0
        max_iterations = 3
        z3_code = state["z3_code"]
        has_z3 = bool(z3_code.strip())

        first_sat_snapshot = None  # remembers the first proven counterexample

        while iterations < max_iterations:

            if has_z3:
                print(f"=== RUNNING Z3 (iteration {iterations + 1}) ===")
                result = self.run_z3(z3_code)
                print("=== Z3 DONE ===", result["status"])

                if result["status"] == "sat" and first_sat_snapshot is None:
                    first_sat_snapshot = {"z3_code": z3_code, "z3_result": result}

                if result["status"] == "unsat":
                    if first_sat_snapshot is not None:
                        # A counterexample was proven earlier in this same run.
                        # A later refined property coming back unsat does NOT
                        # disprove that. Don't silently mark "verified" — flag
                        # for human review instead of erasing the proof.
                        state["status"] = "needs_review"
                        state["z3_result"] = first_sat_snapshot["z3_result"]
                        state["z3_code"] = first_sat_snapshot["z3_code"]
                        state["bug_report"] = (
                            "[CEGIS NOTE] An initial counterexample (SAT) was found in this run, "
                            "but a later refined property returned UNSAT. This does not prove the "
                            "original finding false — the refinement may have over-corrected. "
                            "Manual review required.\n\n"
                            f"Original SAT output:\n{first_sat_snapshot['z3_result']['output']}"
                        )
                        return state
                    state["status"] = "verified"
                    state["z3_result"] = result
                    return state

                z3_section = f"""Z3 RESULT STATUS: {result["status"]}
Z3 OUTPUT: {result["output"]}
Z3 ERROR: {result["error"]}"""
            else:
                print("=== SKIPPING Z3 (slither-only mode, no z3_code) ===")
                z3_section = "Z3 RESULT STATUS: not_applicable (slither-only mode)"

            user_message = f"""
INTENT: {state["intent"]}

Z3 CODE:
{z3_code if has_z3 else "N/A - slither-only mode"}

{z3_section}

SLITHER FINDINGS:
{json.dumps(state.get("slither_result", {}).get("findings", []), indent=2)}
"""

            response = self.agent.invoke([
                SystemMessage(content=self.SYSTEM_PROMPT),
                HumanMessage(content=user_message)
            ])

            raw = response.content
            print("=== CEGIS RAW RESPONSE ===")
            print(raw)
            print("=== END RESPONSE ===")

            if "VERIFIED" in raw:
                state["status"] = "verified"
                return state

            if "BUG FOUND" in raw:
                state["status"] = "bug_found"
                state["bug_report"] = raw
                if has_z3:
                    state["z3_result"] = result  # preserve the actual Z3 model/output for downstream test generation
                return state

            if has_z3 and "```python" in raw:
                z3_code = raw.split("```python")[1].split("```")[0].strip()
            elif has_z3 and "from z3 import *" in raw:
                # Fallback parser if markdown fences are missing from the raw prose response text
                z3_code = "from z3 import *" + raw.split("from z3 import *")[1].strip()
            elif not has_z3:
                break

            iterations += 1

        state["status"] = "needs_review"
        state["z3_code"] = z3_code
        return state