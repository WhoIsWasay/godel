import json
import os
import re
import subprocess
import uuid
import logging

from domain import config

logger = logging.getLogger(__name__)


def has_executed_tests(stdout: str) -> bool:
    """True if forge actually ran test functions (as opposed to dying during
    compilation). Used to disambiguate runtime revert traces containing
    'Error (' from real compile failures."""
    return bool(re.search(r"Ran \d+ tests?", stdout)) or "PASS" in stdout or "FAIL" in stdout


def is_compile_failure(combined_output: str, stdout: str) -> bool:
    """Conservative compile-failure detection. A runtime revert trace that
    merely contains 'Error (' must NOT trigger the LLM heal cycle."""
    if "Compiler run failed" in combined_output:
        return True
    markers = ("ParserError", "TypeError:", "DeclarationError", "SyntaxError",
               "UnimplementedFeatureError", "YulException")
    return any(m in combined_output for m in markers) and not has_executed_tests(stdout)


def classify_forge_json(stdout_text: str):
    """Structured verdict from a `forge test --json` report.

    Returns (verdict, n_tests) with verdict in {'confirmed', 'property_held',
    'harness_error'}, or None when stdout is not a valid JSON report — the
    caller then falls back to the legacy text heuristics. Tolerates forge
    version drift by collecting every boolean 'success' field anywhere in the
    document instead of assuming a fixed schema."""
    s = (stdout_text or "").strip()
    if not (s.startswith("{") or s.startswith("[")):
        return None
    try:
        data = json.loads(s)
    except json.JSONDecodeError:
        return None

    results = []

    def _walk(node):
        if isinstance(node, dict):
            if isinstance(node.get("success"), bool):
                results.append(node["success"])
            for v in node.values():
                _walk(v)
        elif isinstance(node, list):
            for v in node:
                _walk(v)

    _walk(data)
    if not results:
        return ("harness_error", 0)
    if any(r is False for r in results):
        return ("confirmed", len(results))
    return ("property_held", len(results))


class FoundryGatekeeper:
    def __init__(self, project_root: str = ".", verifier_agent=None, debug_dir: str = None):
        self.project_root = project_root
        self.verifier_agent = verifier_agent
        self.test_dir = os.path.join(project_root, "test")
        self.debug_dir = debug_dir or str(config.DEBUG_FOLDER)

        os.makedirs(self.test_dir, exist_ok=True)
        os.makedirs(self.debug_dir, exist_ok=True)
        
    @staticmethod    
    def is_finding_in_scope(finding: dict, result_state: dict) -> bool:
        """
        Gatekeeper Scope Filter: Instantly drops centralization, governance, 
        and design choices that are out-of-scope for Web3 bug bounties.
        """
        # The Isolator emits intent/constraint/target_function/relevant_code/
        # severity_guess/class (see prompts/isolator.txt). Keep legacy keys as
        # fallbacks so externally-supplied findings still work. (H6 fix)
        intent = " ".join([
    str(finding.get("title", "")),
    str(finding.get("vuln_class", "")),
    str(finding.get("class", "")),
    str(finding.get("severity_guess", "")),
    str(finding.get("description", "")),
    str(finding.get("intent", "")),
    str(finding.get("relevant_code", "")),
]).lower()
        raw_report = (result_state.get("bug_report") or "").lower()
    
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

    @staticmethod
    def extract_contract_name(source_code: str, fallback: str = None) -> str:
        """Pick the best 'contract <Name>' declaration from raw source.
        Skips abstract contracts and comments; prefers the candidate matching
        the file stem (guards against interfaces/libraries earlier in file)."""
        from piyoxml import create_index_mask
        masked = create_index_mask(source_code)  # blank out comments/strings
        candidates = []
        for m in re.finditer(r'\b(abstract\s+)?contract\s+([A-Za-z_][A-Za-z0-9_]*)', masked):
            if m.group(1):
                continue
            candidates.append(m.group(2))
        if not candidates:
            return fallback
        if fallback:
            for c in candidates:
                if c.lower() == str(fallback).lower():
                    return c
        return candidates[0]

    def materialize_source(self, source_code: str, real_contract_name: str) -> str:
        """Write the contract into FOUNDRY_ROOT/src/ so forge can compile it.
        Returns the absolute path; caller MUST call cleanup_source() when done
        (a stale file with unresolved imports breaks compilation project-wide)."""
        os.makedirs(str(config.FOUNDRY_ROOT / "src"), exist_ok=True)
        filename = f"{real_contract_name}_{uuid.uuid4().hex[:6]}.sol"
        path = os.path.join(str(config.FOUNDRY_ROOT / "src"), filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(source_code)
        return path

    @staticmethod
    def cleanup_source(path: str):
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass

    def _dump_debug_artifact(self, tag: str, attempt: int, test_code: str, forge_output: str, debug_dir: str = None):
        """Keep a copy of what was actually run and what Forge actually said, so failures are inspectable after the fact."""
        try:
            target_dir = debug_dir or self.debug_dir
            os.makedirs(target_dir, exist_ok=True)
            base = os.path.join(target_dir, f"{tag}_attempt{attempt}")
            with open(f"{base}.t.sol", "w", encoding="utf-8") as f:
                f.write(test_code)
            with open(f"{base}_forge_output.log", "w", encoding="utf-8") as f:
                f.write(forge_output)
            print(f"      [GATEKEEPER DEBUG] Saved candidate + forge output to {base}.t.sol / _forge_output.log")
        except Exception as e:
            logger.warning("[GATEKEEPER WARNING] Could not write debug artifact: %s", e)

    def execute_qc_validation(self, initial_test_code: str, max_retries: int = None, debug_tag: str = "candidate", debug_dir: str = None) -> tuple:
        """Runs Forge against the candidate test suite. Returns (status, forge_output)."""
        if max_retries is None:
            max_retries = config.GATEKEEPER_MAX_RETRIES
        current_test_code = initial_test_code
        
        # ðŸš€ THREAD-SAFE DYNAMIC FILENAMES
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
                    logger.error("[GATEKEEPER ERROR] Failed writing file payload: %s", e)
                    return "tool_error", ""

                if attempt == 1:
                    print("      [GATEKEEPER] Initializing local fuzzing validation via 'forge test'...")
                else:
                    print(f"      [GATEKEEPER] Re-evaluating healed code (Attempt {attempt}/{max_retries})...")
                
                try:
                    result = subprocess.run(
                        [config.FORGE_BIN, "test", "--json", "--match-path", match_path, "-vvv"],
                        capture_output=True,
                        encoding="utf-8",
                        errors="replace",
                        timeout=config.FORGE_TIMEOUT_SECONDS,
                        cwd=self.project_root
                    )

                    stdout = (result.stdout or "").strip()
                    stderr = (result.stderr or "").strip()
                    combined_output = stdout + "\n" + stderr

                    # 2. CEGIS LOOP TRIGGER: Did it fail to compile?
                    #    (Tightened: runtime revert traces containing "Error ("
                    #    no longer trigger unnecessary heal cycles.)
                    if is_compile_failure(combined_output, stdout):
                        self._dump_debug_artifact(debug_tag, attempt, current_test_code, combined_output, debug_dir)
                        if attempt < max_retries and self.verifier_agent:
                            print(f"      [CEGIS WARNING] Compilation failed. Feeding error back to AI for healing...")
                            current_test_code = self.verifier_agent.heal_test_suite(current_test_code, combined_output)
                            continue
                        else:
                            print("      [QC INCONCLUSIVE] Max CEGIS retries reached. Flagging for human review, NOT discarding.")
                            print("\n      ============= ðŸš¨ FINAL COMPILER ERRORS ============= ")
                            print(combined_output)
                            print("      ==================================================== \n")
                            return "compile_failed", combined_output

                    # 2b. HARNESS FAILURE: forge ran but matched zero tests.
                    if "No tests found" in combined_output:
                        self._dump_debug_artifact(debug_tag, attempt, current_test_code, combined_output, debug_dir)
                        print("      [GATEKEEPER ERROR] forge matched zero tests in the generated file â€” harness/match-path problem, not a QC result.")
                        print(combined_output)
                        return "harness_error", combined_output

                    # 2c. STRUCTURED VERDICT: when forge produced a valid JSON
                    # report, classify from it (robust against prose changes
                    # in human-readable output). None -> legacy heuristics.
                    structured = classify_forge_json(stdout)
                    if structured is not None:
                        verdict, n_tests = structured
                        self._dump_debug_artifact(debug_tag, attempt, current_test_code, combined_output, debug_dir)
                        if verdict == "confirmed":
                            print(f"      [QC PASSED] Invariant broken in JSON report ({n_tests} result(s)). Defect is active and verified!")
                        elif verdict == "property_held":
                            print(f"      [QC FAILED] {n_tests} test(s) ran clean but property held (no bug found). Discarding noise.")
                        else:
                            print("      [GATEKEEPER ERROR] JSON report contained zero test results — harness problem.")
                        return verdict, combined_output

                    # 3. SUCCESSFUL EXECUTION: Did the property break? (Bug Proven)
                    if result.returncode != 0 and "FAIL" in stdout:
                        print("      [QC PASSED] Invariant broken successfully. Defect is active and verified!")
                        self._dump_debug_artifact(debug_tag, attempt, current_test_code, combined_output, debug_dir)
                        return "confirmed", combined_output

                    # 3b. ABNORMAL TERMINATION: forge exited non-zero WITHOUT a
                    # FAIL. That is a crash (harness panic, OOM, internal error),
                    # NOT a held property — misclassifying it would silently
                    # discard a genuine bug. Flag as inconclusive instead. (C3 fix)
                    if result.returncode != 0:
                        self._dump_debug_artifact(debug_tag, attempt, current_test_code, combined_output, debug_dir)
                        print("      [QC INCONCLUSIVE] forge aborted abnormally without FAIL "
                              "(crash/OOM/internal error). Flagging for manual review, NOT discarding.")
                        return "inconclusive", combined_output

                    # 4. FALSE POSITIVE: Test compiled cleanly, ran to completion,
                    #    and the invariant held.
                    else:
                        print("      [QC FAILED] Test compiled and ran cleanly but property held (no bug found). Discarding noise.")
                        self._dump_debug_artifact(debug_tag, attempt, current_test_code, combined_output, debug_dir)
                        return "property_held", combined_output

                except subprocess.TimeoutExpired:
                    logger.warning("[GATEKEEPER TIMEOUT] Fuzzing window exceeded %.0fs. Flagging for human review, NOT discarding.",
                                   config.FORGE_TIMEOUT_SECONDS)
                    self._dump_debug_artifact(debug_tag, attempt, current_test_code, "TIMEOUT", debug_dir)
                    return "timeout", "TIMEOUT"
                except FileNotFoundError:
                    logger.critical("[GATEKEEPER CRITICAL] forge binary not found (looked in PATH and "
                                    "~/.foundry/bin; resolved: %r). Install Foundry.", config.FORGE_BIN)
                    return "tool_missing", ""
                except Exception as e:
                    logger.error("[GATEKEEPER ERROR] Structural error: %s", e)
                    return "tool_error", ""

            return "compile_failed", ""
            
        finally:
            # Always clean up the workspace for THIS specific thread's file
            if os.path.exists(target_file):
                try:
                    os.remove(target_file)
                except Exception:
                    pass
