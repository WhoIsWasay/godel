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


# =========================================================================
# INVARIANT WARM-UP RESCUE (MiniVault deposit re-confirm post-mortem)
#
# A PoC for a deterministic exploit is often written as an *invariant* test
# (StdInvariant + `invariant_*`) whose body drives the real state sequence
# through public calls and then asserts the SAFE invariant. When that assert
# fires, the exploit has genuinely reproduced on the EVM. But Foundry reports
# an assertion that reverts during the invariant harness warm-up as:
#
#     status: Failure
#     reason: "failed to set up invariant testing environment: <assert msg>: 0 <= 0"
#     kind:   Invariant, runs: 0
#
# The blanket setUp-marker pre-check used to map ANY output containing
# "failed to set up invariant" to harness_error BEFORE reading the structured
# JSON — so a real reproduction was routed into the "fix setUp()" heal loop
# (setUp is fine; nothing to heal) and eventually shipped as [UNVERIFIED]
# informational. The revert reason that reaches us is the PoC's OWN assertion
# message, which is the strongest possible signal that the property check ran
# and failed. We rescue it here:
#
#   - only genuinely unreachable harness problems stay harness_error:
#     vm.etch on a precompile, missing selector, setUp() revert, or an
#     invariant warm-up failure whose inner reason is NOT one of the PoC's
#     assertion messages (i.e. an infra/deploy/constructor problem).
#   - a warm-up failure whose inner reason IS an assertion message present in
#     the PoC test code and overlapping the finding's property wording is a
#     clean EVM reproduction -> confirmed.
# =========================================================================
_INVARIANT_SETUP_PREFIX = "failed to set up invariant testing environment"

_HARD_INFRA_MARKERS = (
    "vm.etch: cannot use precompile",
    "does not have the selector",
    "setUp() must be",
)

_SETUP_FAIL_MARKERS = (
    "setup failed", "set failed", "failed to set up",  # lowercased match
)

_NUMERIC_ASSERT_TAIL_RE = re.compile(r":\s*\d+\s*(<=|>=|!=|==|<|>)\s*\d+\s*$")

_PROPERTY_STOPWORDS = frozenset(
    "this that with from the and when after before must should have into "
    "than then not null true false error failed".split()
)

# When the raw combined output is scanned (legacy text path) the assertion
# message is followed by JSON/forge noise; cut at the first of these delimiters.
_BOUNDARY_CUTS = ('","', '"}', '"', "\n")


def _property_candidate(reason_text: str) -> str:
    """Pull the assertion message out of a forge failure reason.

    Handles the invariant warm-up wrapper (`failed to set up invariant testing
    environment: <msg>: 0 <= 0`) and strips forge-std's numeric comparison
    tail (": a <= b"). When fed a chunk of combined output, also cuts at JSON
    boundaries / newlines so only the message on the same line survives."""
    t = (reason_text or "")
    if _INVARIANT_SETUP_PREFIX in t:
        t = t.split(_INVARIANT_SETUP_PREFIX, 1)[1]
        t = t.lstrip(": \"").strip()
        for cut in _BOUNDARY_CUTS:
            if cut in t:
                t = t.split(cut, 1)[0].rstrip().rstrip(":")
                break
    t = _NUMERIC_ASSERT_TAIL_RE.sub("", t).strip()
    return t.strip()


def _overlaps_property_wording(message: str, finding_intent: str) -> bool:
    """True when the assertion message shares >= 2 significant words with the
    finding's property wording. Property asserts echo the invariant/intent
    ("positive deposit minted zero shares"); state-precondition asserts and
    infra/constructor errors do not ("witness totalSupply mismatch")."""
    hay = (finding_intent or "").lower()
    if not hay or len(message) < 5:
        return False
    tokens = [t for t in re.findall(r"[A-Za-z][A-Za-z0-9]{3,}", message)
              if t.lower() not in _PROPERTY_STOPWORDS]
    if not tokens:
        return False
    hits = sum(1 for t in tokens if t.lower() in hay)
    return hits >= 2


def _property_assertion_fired(reason_text: str, test_code: str, finding_intent: str) -> bool:
    """A warm-up failure whose inner reason is the PoC's own safe-invariant
    assertion message (present in the test code AND overlapping the finding's
    wording) is an EVM reproduction of the bug, not a harness problem."""
    if not reason_text or _INVARIANT_SETUP_PREFIX not in reason_text:
        return False
    cand = _property_candidate(reason_text)
    if not cand or len(cand) > 160:
        return False
    code = test_code or ""
    if cand not in code:
        return False
    return _overlaps_property_wording(cand, finding_intent)


def _classify_failure_reason(reason_text: str, test_code: str = "", finding_intent: str = ""):
    """Map one forge Failure reason to a verdict hint:
      'confirmed'     -> the PoC's own safe-invariant assertion fired on the EVM
      'harness_error' -> genuine setUp/infra problem (test never meaningfully ran)
      None            -> undecidable here; caller uses the structural default."""
    if not reason_text:
        return None
    if _property_assertion_fired(reason_text, test_code, finding_intent):
        return "confirmed"
    lowered = reason_text.lower()
    if _INVARIANT_SETUP_PREFIX in reason_text:
        # Warm-up failure whose inner reason is NOT one of the PoC's property
        # assertions (deploy/constructor/mock/cheatcode problem) — keep it a
        # harness error, never guess.
        return "harness_error"
    if any(m in lowered for m in _HARD_INFRA_MARKERS) or any(
            m in lowered for m in _SETUP_FAIL_MARKERS):
        return "harness_error"
    return None


def classify_forge_json(stdout_text: str, combined_output: str = "",
                        test_code: str = "", finding_intent: str = ""):
    """Structured verdict from a `forge test --json` report.

    Returns (verdict, n_tests) with verdict in {'confirmed', 'property_held',
    'harness_error'}, or None when stdout is not a valid JSON report — the
    caller then falls back to the legacy text heuristics. Tolerates forge
    version drift by collecting every boolean 'success' field anywhere in the
    document instead of assuming a fixed schema. Newer forge versions replace
    the boolean 'success' field with 'status': 'Success'/'Failure' — both are
    collected.

    setUp/infra failures (vm.etch precompile, selector errors, setUp reverts)
    are classified as harness_error, NOT confirmed — a test that never ran
    cannot disprove an invariant. Exception: an invariant warm-up failure whose
    revert reason is the PoC's own safe-invariant assertion message is a real
    EVM reproduction and is returned as 'confirmed' (see the rescue block
    above). `test_code` and `finding_intent` are used to tell the two apart."""
    s = (stdout_text or "").strip()
    if not (s.startswith("{") or s.startswith("[")):
        return None
    try:
        data = json.loads(s)
    except json.JSONDecodeError:
        return None

    results = []
    failure_reasons = []

    def _walk(node, key=None):
        if key == "traces":
            return
        if isinstance(node, dict):
            status = node.get("status")
            if isinstance(status, str) and status in ("Success", "Failure"):
                results.append(status == "Success")
                if status == "Failure" and isinstance(node.get("reason"), str):
                    failure_reasons.append(node["reason"])
            elif isinstance(node.get("success"), bool):
                results.append(node["success"])
            for k, v in node.items():
                _walk(v, k)
        elif isinstance(node, list):
            for v in node:
                _walk(v, key)

    _walk(data)
    if not results and not failure_reasons:
        return ("harness_error", 0)

    n_tests = len(results) if results else len(failure_reasons)

    for reason in failure_reasons:
        hint = _classify_failure_reason(reason, test_code, finding_intent)
        if hint == "harness_error":
            # A genuinely unreachable setUp/infra problem anywhere in the run
            # overrides any sibling success — never read it as a bug.
            return ("harness_error", 0)
        # 'confirmed' hints accumulate below; None defers to the bools.
    confirmed_via_reason = any(
        _classify_failure_reason(r, test_code, finding_intent) == "confirmed"
        for r in failure_reasons)

    # Infra markers that appear outside a per-test reason (e.g. a nested
    # setup node) must still cap the verdict — unless a property assertion
    # already proved the bug, in which case the reproduction wins.
    if not confirmed_via_reason:
        lowered = (combined_output or "").lower()
        if any(m in lowered for m in _HARD_INFRA_MARKERS) or any(
                m in lowered for m in _SETUP_FAIL_MARKERS):
            return ("harness_error", 0)

    if confirmed_via_reason or any(r is False for r in results):
        return ("confirmed", n_tests)
    return ("property_held", n_tests)


def downgrade_forced_confirmation(verdict: str, test_code: str) -> str:
    """A forge FAIL is only a SOUND confirmation when the PoC reached the
    vulnerable state through real public/external calls. If it instead
    force-constructs storage via vm.store/vm.etch, the FAIL merely
    re-demonstrates the state Z3 *assumed* — it never proves that state is
    reachable. Downgrade 'confirmed' to 'confirmed_forced' in that case so it
    is surfaced as a reachability-unproven lead (manual review, capped
    severity), never as a clean confirmed vulnerability. Other verdicts pass
    through untouched."""
    if verdict != "confirmed":
        return verdict
    from domain.schema import detect_forced_state
    return "confirmed_forced" if detect_forced_state(test_code) else verdict


def _finding_property_wording(finding) -> str:
    """Concatenate the natural-language description of the property under test
    from a finding dict (both OUTPUT shape and INPUT shape keys). Used to
    recognize the PoC's safe-invariant assertion message inside a forge
    failure reason."""
    if not isinstance(finding, dict):
        return ""
    parts = [
        finding.get("intent"), finding.get("summary"),
        finding.get("constraint"), finding.get("root_cause"),
        finding.get("relevant_code"), finding.get("invariant"),
        finding.get("title"),
    ]
    text = " ".join(str(p) for p in parts if p)
    return text[:1500]


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

    def execute_qc_validation(self, initial_test_code: str, max_retries: int = None, debug_tag: str = "candidate", debug_dir: str = None, legacy: bool = False, target_source: str = None, finding: dict = None) -> tuple:
        """Runs Forge against the candidate test suite. Returns (status, forge_output).

        legacy=True means the target's pragma excludes solc >= 0.8.13, so
        forge-std cannot compile; suites importing it are healed
        deterministically instead of burning a doomed forge invocation.
        target_source (when given alongside legacy) enables the deterministic
        pragma-conflict pre-check: a suite whose pragma shares no solc version
        with the target can never compile. `finding` supplies the property
        wording used to tell an invariant warm-up assertion failure (a real EVM
        reproduction -> confirmed) apart from a genuine setUp/infra problem."""
        if max_retries is None:
            max_retries = config.GATEKEEPER_MAX_RETRIES
        from domain.solc_compat import LEGACY_HEAL_HINT
        current_test_code = initial_test_code
        finding_intent = _finding_property_wording(finding)
        
        # ðŸš€ THREAD-SAFE DYNAMIC FILENAMES
        unique_id = uuid.uuid4().hex[:6]
        thread_file_name = f"QC_Verify_{debug_tag}_{unique_id}.t.sol"
        target_file = os.path.join(self.test_dir, thread_file_name)
        match_path = os.path.join("test", thread_file_name).replace("\\", "/")

        try:
            for attempt in range(1, max_retries + 1):
                # 0. LEGACY PRE-CHECK: forge-std imports are a guaranteed
                # compile failure for sub-0.8.13 targets — heal before ever
                # invoking forge. Import statements are located in the
                # comment-masked text (so comments mentioning forge-std can't
                # trigger a false heal) and checked against the original text,
                # because the mask blanks string contents. A second trigger:
                # the suite's pragma sharing no solc version with the target
                # (forge builds with ONE version, so it can never compile).
                from piyoxml import create_index_mask
                from domain.solc_compat import pragmas_conflict, pragma_statements
                _masked = create_index_mask(current_test_code)
                _legacy_import = any(
                    "forge-std" in current_test_code[m.start():m.end()]
                    for m in re.finditer(r'\bimport\b[^;]+;', _masked)
                )
                _pragma_conflict = bool(
                    legacy and target_source
                    and pragmas_conflict(current_test_code, target_source)
                )
                if legacy and (_legacy_import or _pragma_conflict):
                    reasons = []
                    if _legacy_import:
                        reasons.append("it imports forge-std, which requires solc >= 0.8.13, "
                                       "but the target contract's pragma forbids it")
                    if _pragma_conflict:
                        _suite_pragmas = "; ".join(pragma_statements(current_test_code)) or "none"
                        _target_pragmas = "; ".join(pragma_statements(target_source)) or "unknown"
                        reasons.append(f"it declares `pragma solidity {_suite_pragmas}` while the "
                                       f"target requires `pragma solidity {_target_pragmas}` — no "
                                       f"single solc version can compile both; mirror the target's "
                                       f"pragma in the suite")
                    print("      [CEGIS WARNING] Legacy pre-check tripped "
                          "(forge-std import / pragma conflict) — healing without invoking forge...")
                    synthetic_error = ("Compiler run failed (deterministic pre-check): "
                                       + "; ".join(reasons) + ".\n" + LEGACY_HEAL_HINT)
                    if attempt < max_retries and self.verifier_agent:
                        current_test_code = self.verifier_agent.heal_test_suite(
                            current_test_code, synthetic_error, legacy=True)
                        continue
                    self._dump_debug_artifact(debug_tag, attempt, current_test_code, synthetic_error, debug_dir)
                    return "compile_failed", synthetic_error

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
                            heal_error = combined_output
                            # Legacy targets: the classic failure is a forge-std
                            # version clash — make the constraint explicit so the
                            # repair cannot re-introduce the same import.
                            if legacy and ("forge-std" in combined_output or "0.8.13" in combined_output):
                                heal_error = combined_output + "\n\n" + LEGACY_HEAL_HINT
                            current_test_code = self.verifier_agent.heal_test_suite(
                                current_test_code, heal_error, legacy=legacy)
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
                    structured = classify_forge_json(
                        stdout, combined_output,
                        test_code=current_test_code, finding_intent=finding_intent)
                    if structured is not None:
                        verdict, n_tests = structured
                        verdict = downgrade_forced_confirmation(verdict, current_test_code)
                        self._dump_debug_artifact(debug_tag, attempt, current_test_code, combined_output, debug_dir)
                        if verdict == "confirmed":
                            print(f"      [QC PASSED] Invariant broken in JSON report ({n_tests} result(s)). Defect is active and verified!")
                            return verdict, combined_output
                        elif verdict == "confirmed_forced":
                            print("      [QC FORCED-STATE] Invariant broke, but the PoC force-constructs the storage state (vm.store/vm.etch). Natural reachability NOT proven — flagging for manual review, not a clean confirmation.")
                            return verdict, combined_output
                        elif verdict == "property_held":
                            print(f"      [QC FAILED] {n_tests} test(s) ran clean but property held (no bug found). Discarding noise.")
                            return verdict, combined_output
                        elif verdict == "harness_error" and attempt < max_retries and self.verifier_agent:
                            print("      [CEGIS WARNING] setUp failure detected. Feeding error back to AI for healing...")
                            heal_error = combined_output + "\n\nSETUP ERROR: The test failed during setUp(), not during invariant checking. Fix the setUp() function — common causes: vm.etch on precompile addresses (0x1-0x9), wrong constructor arguments, missing mock setup."
                            current_test_code = self.verifier_agent.heal_test_suite(
                                current_test_code, heal_error, legacy=legacy)
                            continue
                        else:
                            print("      [GATEKEEPER ERROR] JSON report contained zero test results — harness problem.")
                        return verdict, combined_output

                    # 3. SUCCESSFUL EXECUTION: Did the property break? (Bug Proven)
                    if result.returncode != 0 and "FAIL" in stdout:
                        # A setUp-phase revert can be a genuine harness problem
                        # (vm.etch on a precompile, wrong constructor args, ...)
                        # OR the PoC's own safe-invariant assertion firing inside
                        # the invariant warm-up — which is an EVM reproduction.
                        # Only the former is a harness_error; the latter is a bug.
                        hint = _classify_failure_reason(
                            combined_output, current_test_code, finding_intent)
                        if hint == "harness_error":
                            print("      [GATEKEEPER ERROR] Test failed at setUp — "
                                  "harness problem, NOT a confirmed bug.")
                            self._dump_debug_artifact(debug_tag, attempt, current_test_code, combined_output, debug_dir)
                            return "harness_error", combined_output
                        verdict = downgrade_forced_confirmation("confirmed", current_test_code)
                        if verdict == "confirmed_forced":
                            print("      [QC FORCED-STATE] Invariant broke, but the PoC force-constructs the storage state (vm.store/vm.etch). Natural reachability NOT proven — flagging for manual review, not a clean confirmation.")
                        elif hint == "confirmed":
                            print("      [QC PASSED] Invariant warm-up assertion failed — the PoC's own property check reproduced the bug on the EVM!")
                        else:
                            print("      [QC PASSED] Invariant broken successfully. Defect is active and verified!")
                        self._dump_debug_artifact(debug_tag, attempt, current_test_code, combined_output, debug_dir)
                        return verdict, combined_output

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
