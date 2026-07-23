import os
import subprocess
import uuid

class FoundryGatekeeper:
    def __init__(self, project_root: str = ".", verifier_agent=None, debug_dir: str = "output/debug_tests"):
        self.project_root = project_root
        self.verifier_agent = verifier_agent
        self.test_dir = os.path.join(project_root, "test")
        self.debug_dir = debug_dir

        os.makedirs(self.test_dir, exist_ok=True)
        os.makedirs(self.debug_dir, exist_ok=True)

    def is_finding_in_scope(finding: dict, result_state: dict) -> bool:
        """
        Gatekeeper Scope Filter: Instantly drops centralization, governance, 
        and design choices that are out-of-scope for Web3 bug bounties.
        """
        intent = finding.get("intent", "").lower()
        raw_report = result_state.get("bug_report", "").lower()
    
        # 1. Drop if the scanner explicitly stated the code is valid/safe
        if "logic adheres to safety invariants" in raw_report:
            print(f"   [SCOPE GATEKEEPER] Dropping finding {finding.get('id')}: Code was verified safe by scanner.")
            return False
        
        # 2. Block out-of-scope architectural and centralization risks
        out_of_scope_keywords = [
            "timelock", "multisig", "multi-signature", "governance delay", 
            "centralization risk", "single-step ownership", "missing-zero-check",
            "ownable2step", "access control modifier"
        ]
    
        for keyword in out_of_scope_keywords:
            if keyword in intent or keyword in raw_report:
                print(f"   [SCOPE GATEKEEPER] Dropping finding {finding.get('id')}: Identified as out-of-scope risk ({keyword}).")
                return False
            
        return True

    def _dump_debug_artifact(self, tag: str, attempt: int, test_code: str, forge_output: str):
        """Keep a copy of what was actually run and what Forge actually said, so failures are inspectable after the fact."""
        try:
            base = os.path.join(self.debug_dir, f"{tag}_attempt{attempt}")
            with open(f"{base}.t.sol", "w", encoding="utf-8") as f:
                f.write(test_code)
            with open(f"{base}_forge_output.log", "w", encoding="utf-8") as f:
                f.write(forge_output)
            print(f"      [GATEKEEPER DEBUG] Saved candidate + forge output to {base}.t.sol / _forge_output.log")
        except Exception as e:
            print(f"      [GATEKEEPER WARNING] Could not write debug artifact: {e}")

    def execute_qc_validation(self, initial_test_code: str, max_retries: int = 3, debug_tag: str = "candidate") -> str:
        current_test_code = initial_test_code
        
        # 🚀 THREAD-SAFE DYNAMIC FILENAMES
        unique_id = uuid.uuid4().hex[:6]
        thread_file_name = f"QC_Verify_{debug_tag}_{unique_id}.t.sol"
        target_file = os.path.join(self.test_dir, thread_file_name)
        match_path = os.path.join("test", thread_file_name).replace("\\", "/")

        try:
            for attempt in range(1, max_retries + 1):
                # 1. Write the payload
                try:
                    with open(target_file, "w", encoding="utf-8") as f:
                        f.write(current_test_code)
                except Exception as e:
                    print(f"      [GATEKEEPER ERROR] Failed writing file payload: {e}")
                    return "tool_error"

                if attempt == 1:
                    print("      [GATEKEEPER] Initializing local fuzzing validation via 'forge test'...")
                else:
                    print(f"      [GATEKEEPER] Re-evaluating healed code (Attempt {attempt}/{max_retries})...")
                
                try:
                    result = subprocess.run(
                        ["forge", "test", "--match-path", match_path, "-vvv"],
                        capture_output=True,
                        encoding="utf-8",
                        errors="replace",
                        timeout=45,
                        cwd=self.project_root
                    )
                    
                    stdout = (result.stdout or "").strip()
                    stderr = (result.stderr or "").strip()
                    combined_output = stdout + "\n" + stderr

                    # 2. CEGIS LOOP TRIGGER: Did it fail to compile?
                    if "Compiler run failed" in combined_output or "Error (" in combined_output:
                        self._dump_debug_artifact(debug_tag, attempt, current_test_code, combined_output)
                        if attempt < max_retries and self.verifier_agent:
                            print(f"      [CEGIS WARNING] Compilation failed. Feeding error back to AI for healing...")
                            current_test_code = self.verifier_agent.heal_test_suite(current_test_code, combined_output)
                            continue
                        else:
                            print("      [QC INCONCLUSIVE] Max CEGIS retries reached. Flagging for human review, NOT discarding.")
                            print("\n      ============= 🚨 FINAL COMPILER ERRORS ============= ")
                            print(combined_output)
                            print("      ==================================================== \n")
                            return "compile_failed"

                    # 2b. HARNESS FAILURE: forge ran but matched zero tests. 
                    if "No tests found" in combined_output:
                        self._dump_debug_artifact(debug_tag, attempt, current_test_code, combined_output)
                        print("      [GATEKEEPER ERROR] forge matched zero tests in the generated file — harness/match-path problem, not a QC result.")
                        print(combined_output)
                        return "harness_error"

                    # 3. SUCCESSFUL EXECUTION: Did the property break? (Bug Proven)
                    if result.returncode != 0 and "FAIL" in stdout:
                        print("      [QC PASSED] Invariant broken successfully. Defect is active and verified!")
                        self._dump_debug_artifact(debug_tag, attempt, current_test_code, combined_output)
                        return "confirmed"
                    
                    # 4. FALSE POSITIVE: Test compiled cleanly, but invariant held.
                    else:
                        print("      [QC FAILED] Test compiled successfully but property held (no bug found). Discarding noise.")
                        self._dump_debug_artifact(debug_tag, attempt, current_test_code, combined_output)
                        return "property_held"

                except subprocess.TimeoutExpired:
                    print("      [GATEKEEPER TIMEOUT] Fuzzing window exceeded 45s. Flagging for human review, NOT discarding.")
                    self._dump_debug_artifact(debug_tag, attempt, current_test_code, "TIMEOUT")
                    return "timeout"
                except FileNotFoundError:
                    print("      [GATEKEEPER CRITICAL] 'forge' binary not found in system PATH. Install Foundry.")
                    return "tool_missing"
                except Exception as e:
                    print(f"      [GATEKEEPER ERROR] Structural error: {e}")
                    return "tool_error"

            return "compile_failed"
            
        finally:
            # Always clean up the workspace for THIS specific thread's file
            if os.path.exists(target_file):
                try:
                    os.remove(target_file)
                except Exception:
                    pass