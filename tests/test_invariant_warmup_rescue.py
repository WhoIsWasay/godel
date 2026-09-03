"""Invariant warm-up rescue: zero-credit regression tests.

WHY THIS FILE EXISTS
--------------------
A warm-seeded MiniVault re-confirm generated a *correct* PoC that drove the
vulnerable state through real public calls and asserted the SAFE invariant:

    assertGt(bobSharesAfter, bobSharesBefore,
             "positive deposit minted zero shares");

On the EVM that assert FIRED (the bug reproduced: "0 <= 0"). But because it
fired inside the Foundry invariant-testing harness warm-up, forge reported

    status: Failure
    reason: "failed to set up invariant testing environment: positive
             deposit minted zero shares: 0 <= 0"
    kind:   Invariant, runs: 0

classify_forge_json's blanket setUp-marker pre-check mapped ANY output
containing "failed to set up invariant" to harness_error BEFORE reading the
structured JSON, so the reproduction was thrown into the "fix setUp()" heal
loop (nothing to fix) and shipped as [UNVERIFIED] informational.

These tests pin the rescue: with the PoC code and the finding's property
wording supplied (as the pipeline now does), that exact failure confirms; a
genuine infra setUp problem (vm.etch on a precompile, missing selector,
constructor revert) still stays harness_error. No LLM, no forge binary, no
credits — subprocess.run is monkeypatched.

Run with: pytest tests/test_invariant_warmup_rescue.py -v
"""

import sys
import json
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from unittest.mock import patch  # noqa: E402

# The failure reason exactly as forge emitted it for the real MiniVault run.
_WRAPPER_REASON = ("failed to set up invariant testing environment: "
                   "positive deposit minted zero shares: 0 <= 0")

# The assertion message the PoC authored (a literal inside the test code).
_ASSERT_MSG = "positive deposit minted zero shares"

# Faithful excerpt of the real forge --json report structure.
REAL_STYLE_JSON = json.dumps({
    "test/QC_Verify_MiniVault_verify_43cf6c.t.sol:PropertyTest": {
        "duration": "6ms 428us 300ns",
        "test_results": {
            "invariant_property_verification()": {
                "status": "Failure",
                "reason": _WRAPPER_REASON,
                "counterexample": None,
                "kind": {"Invariant": {
                    "runs": 0, "calls": 0, "reverts": 0,
                    "failed_corpus_replays": 0}},
            }
        }
    }
})

# The generated PoC (structure faithful to what the model produced; public
# calls only, NO vm.store/etch).
REAL_STYLE_POC = """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {MiniVault} from "src/MiniVault_5836c6.sol";

contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
    function approve(address s, uint256 a) external returns (bool) { allowance[msg.sender][s] = a; return true; }
    function transferFrom(address f, address t, uint256 a) external returns (bool) {
        allowance[f][msg.sender] -= a; balanceOf[f] -= a; balanceOf[t] += a; return true;
    }
}

contract PropertyTest is Test {
    MiniVault private vault;
    address private constant ALICE = address(0xA11CE);
    address private constant BOB = address(0xB0B);
    bool private witnessPrepared;

    function setUp() public {
        MockERC20 token = new MockERC20();
        vault = new MiniVault(address(token));
        token.mint(ALICE, 1000);
        token.mint(BOB, 1);
        vm.startPrank(ALICE); token.approve(address(vault), type(uint256).max); vm.stopPrank();
        vm.startPrank(BOB); token.approve(address(vault), type(uint256).max); vm.stopPrank();
        targetContract(address(vault));
    }

    function invariant_property_verification() public {
        if (!witnessPrepared) {
            vm.startPrank(ALICE);
            vault.deposit(1000);
            vault.emergencyWithdraw(999);
            vault.deposit(499);
            vm.stopPrank();
            witnessPrepared = true;
        }
        uint256 before = vault.balances(BOB);
        vm.prank(BOB);
        vault.deposit(1);
        assertGt(vault.balances(BOB), before, "%s");
    }
}
""" % _ASSERT_MSG

_INTENT = ("A non-zero deposit can mint zero shares when the share price is "
           "high, because (assets * totalSupply) / totalAssets truncates to 0. "
           "emergencyWithdraw subtracts a flat 500 instead of 5%.")


def _run_qc(test_code, stdout_json, err="", finding=None, exit_code=1):
    """execute_qc_validation with forge fully mocked out."""
    from domain.gatekeeper import FoundryGatekeeper
    import tempfile

    class _Proc:
        returncode = exit_code
        stdout = stdout_json
        stderr = err

    with tempfile.TemporaryDirectory(prefix="gk_rescue_") as tmpdir:
        gk = FoundryGatekeeper(project_root=tmpdir, verifier_agent=None,
                               debug_dir=str(Path(tmpdir) / "dbg"))
        with patch.object(subprocess, "run", return_value=_Proc()):
            return gk.execute_qc_validation(
                test_code, max_retries=1, debug_tag="rescue",
                finding=finding)


# ----------------------------------------------------------------- CLASSIFIER

def test_real_style_wrapper_confirms_with_context():
    from domain.gatekeeper import classify_forge_json
    assert classify_forge_json(REAL_STYLE_JSON, REAL_STYLE_JSON,
                               test_code=REAL_STYLE_POC,
                               finding_intent=_INTENT) == ("confirmed", 1)


def test_real_style_wrapper_without_context_stays_harness_error():
    # Backward-compatible default: no PoC/finding context -> conservative.
    from domain.gatekeeper import classify_forge_json
    assert classify_forge_json(REAL_STYLE_JSON, REAL_STYLE_JSON) == ("harness_error", 0)


def test_property_candidate_strips_wrapper_and_numeric_tail():
    from domain.gatekeeper import _property_candidate
    assert _property_candidate(_WRAPPER_REASON) == _ASSERT_MSG


def test_precondition_mismatch_is_not_property():
    # A precondition assert that fails ("witness totalSupply mismatch") means the
    # exploit sequence diverged BEFORE the property assert — never a confirmation.
    from domain.gatekeeper import _property_assertion_fired
    reason = ("failed to set up invariant testing environment: "
              "witness totalSupply mismatch: 1 != 0")
    code = REAL_STYLE_POC + "\n    assertEq(vault.totalSupply(), 1, \"witness totalSupply mismatch\");"
    assert _property_assertion_fired(reason, code, _INTENT) is False


def test_infra_vm_etch_wrapper_is_harness_error():
    from domain.gatekeeper import classify_forge_json
    json_report = json.dumps({
        "T": {"test_results": {"i()": {
            "status": "Failure",
            "reason": ("failed to set up invariant testing environment: "
                       "vm.etch: cannot use precompile")}}}
    })
    assert classify_forge_json(json_report, json_report,
                               test_code=REAL_STYLE_POC,
                               finding_intent=_INTENT) == ("harness_error", 0)


def test_missing_selector_is_harness_error():
    from domain.gatekeeper import classify_forge_json
    json_report = json.dumps({
        "T": {"test_results": {"x()": {
            "status": "Failure",
            "reason": "does not have the selector"}}}
    })
    assert classify_forge_json(json_report, json_report) == ("harness_error", 0)


def test_unknown_wrapper_inner_is_harness_error():
    # A warm-up failure whose inner reason is NOT one of the PoC's assertion
    # messages (e.g. a constructor/deploy revert) must not be guessed as a bug.
    from domain.gatekeeper import classify_forge_json
    json_report = json.dumps({
        "T": {"test_results": {"i()": {
            "status": "Failure",
            "reason": "failed to set up invariant testing environment: "
                      "Error: new MiniVault reverted"}}}
    })
    assert classify_forge_json(json_report, json_report,
                               test_code=REAL_STYLE_POC,
                               finding_intent=_INTENT) == ("harness_error", 0)


def test_legacy_boolean_failure_still_confirms():
    # success:false without a reason -> plain FAIL, unchanged semantics.
    from domain.gatekeeper import classify_forge_json
    j = '{"T":{"test_a":{"success": true},"test_b":{"success": false}}}'
    assert classify_forge_json(j, j) == ("confirmed", 2)


def test_all_pass_is_property_held():
    from domain.gatekeeper import classify_forge_json
    j = '{"VaultTest":{"test_x":{"success": true}},"OtherTest":{"test_y":{"success": true}}}'
    assert classify_forge_json(j, j) == ("property_held", 2)


def test_empty_json_is_harness_error():
    from domain.gatekeeper import classify_forge_json
    assert classify_forge_json("{}", "{}") == ("harness_error", 0)


def test_non_json_is_none():
    from domain.gatekeeper import classify_forge_json
    assert classify_forge_json("Ran 1 tests: PASS") is None


# --------------------------------------------------------------- END-TO-END QC

def test_execute_qc_confirms_real_wrapper_failure():
    status, _ = _run_qc(REAL_STYLE_POC, REAL_STYLE_JSON,
                        finding={"intent": _INTENT})
    assert status == "confirmed"


def test_execute_qc_property_held_when_clean():
    clean = json.dumps({"T": {"test_results": {"t()": {"status": "Success"}}}})
    status, _ = _run_qc("// any", clean, exit_code=0)
    assert status == "property_held"


def test_execute_qc_infra_wrapper_still_harness_error():
    infra = json.dumps({"T": {"test_results": {"i()": {
        "status": "Failure",
        "reason": ("failed to set up invariant testing environment: "
                   "vm.etch: cannot use precompile")}}}})
    status, _ = _run_qc(REAL_STYLE_POC, infra, finding={"intent": _INTENT})
    assert status == "harness_error"


def test_forced_state_invariant_poc_is_downgraded_not_clean():
    # Even when the warm-up rescue fires, a PoC that vm.store's the state must
    # come out as confirmed_forced (reachability unproven), never clean.
    forced_poc = REAL_STYLE_POC + "\n    vm.store(address(vault), bytes32(uint256(0)), bytes32(uint256(1)));"
    status, _ = _run_qc(forced_poc, REAL_STYLE_JSON,
                        finding={"intent": _INTENT})
    assert status == "confirmed_forced"


# ------------------------------------------------- REAL ARTIFACT (if present)
def test_real_saved_artifact_now_confirms(tmp_path):
    """Replay the EXACT forge JSON from the MiniVault run that shipped as
    harness_error. Skipped when the artifact is not on disk (CI)."""
    artifact = (PROJECT_ROOT / "output" / "submissions" / "MiniVault"
                / "deposit_ac1750" / "finding.json")
    if not artifact.exists():
        import pytest
        pytest.skip("saved artifact not present in this checkout")
    finding = json.loads(artifact.read_text(encoding="utf-8"))
    combined = finding["forge_output"]
    # split combined (stdout JSON + "\n" + stderr) back into pure stdout
    stdout, _end = json.JSONDecoder().raw_decode(combined)
    stdout = combined[:_end]
    code = finding["poc_test_code"]
    intent = " ".join(str(finding.get(k) or "") for k in
                      ("summary", "root_cause", "invariant"))
    from domain.gatekeeper import classify_forge_json
    assert finding["qc_status"] == "harness_error"  # what actually shipped
    verdict = classify_forge_json(stdout, combined, test_code=code,
                                  finding_intent=intent)
    assert verdict[0] == "confirmed"


# ------------------------------------------------- SOUNDNESS GUARD (unchanged)
def test_harness_error_is_still_capped_when_it_happens():
    from domain.schema import build_finding
    from domain.schema import detect_forced_state
    finding = {"target_function": "deposit",
               "intent": "zero-share mint", "severity_guess": "high"}
    state = {"contract_name": "MiniVault", "z3_result": {},
             "z3_code": "", "iterations": 1}
    out = build_finding(finding, state, "", "", "", "harness_error")
    assert out["qc_status"] == "harness_error"
    assert out["metadata"]["verified"] is False
    assert out["severity"] == "informational"
    assert detect_forced_state(REAL_STYLE_POC) is False
