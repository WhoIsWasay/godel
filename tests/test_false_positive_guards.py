"""
Offline guards against the false-positive / duplicate / claim-mismatch classes
exposed by the MiniVault "Godel Realtest" run.

Every test here is pure (no LLM, no z3 subprocess, no forge): it exercises the
deterministic guard logic that now prevents each issue from ever shipping.

Covered:
  A. semantics  — havocked (loop/unencodable) locals are surfaced as
                  `unbound_locals` and emitted into the harness `_unbound_locals`.
  B. z3_runner  — the strict lint REJECTS a property that asserts on a havocked
                  symbol (the vacuous `V['loc_shares'] == 0` "confirmed" proof),
                  ACCEPTS it once the symbol is bound, and stays backward
                  compatible with standalone scripts that have no harness list.
  C. schema     — unverified findings are capped to informational/[UNVERIFIED];
                  forced-state PoCs and the real forge assertion are recorded.
  D. formatter  — the report gains a VERIFICATION STATUS block; unverified
                  findings never render as a confirmed severity.
  E. inspector  — dedup merges same-root-cause twins (identical tiny code locus)
                  regardless of paraphrased intent, and retains higher severity.

Run: python -m pytest tests/test_false_positive_guards.py -v
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from domain.semantics import HarnessEncoder
from domain import z3_runner
from domain.schema import build_finding, detect_forced_state, extract_qc_reason
from domain.formatter import SubmissionFormatter
from domain.inspector import Inspector


# ===========================================================================
# A. SEMANTICS — havocked locals are exposed as unbound_locals
# ===========================================================================
def _fn(**overrides):
    base = {
        "full_name": "deposit(uint256)",
        "visibility": "public", "modifiers": [],
        "params": [{"name": "assets", "type": "uint256"}],
        "returns_types": [],
        "nodes": 5, "edges": 4, "loops": 0,
        "state_writes": ["totalShares"],
        "state_reads": [],
        "external_calls": [],
        "has_external_call": False,
        "guards": [],
        "assignments": [],
        "first_external_call_order": None,
        "branch_conditions_src": [], "has_branch": False,
        "returns_expr": None, "internal_calls": [],
        "branches": [], "payable": False,
    }
    base.update(overrides)
    return base


def _analysis(fn):
    return {
        "contract": "MiniVault",
        "functions": {"deposit(uint256)": fn},
        "storage_layout": [{"name": "totalShares", "type": "uint256"}],
    }


class TestSemanticsUnboundLocals:
    def test_havocked_local_is_unbound(self):
        # A local write under a loop context cannot be encoded: the symbol is
        # registered but NO defining equality is emitted -> it stays free.
        fn = _fn(assignments=[
            {"op": "=", "lhs": "shares", "rhs": "assets", "order": 0,
             "when": [{"c": "i < n", "loop": True}]},
        ])
        harness = HarnessEncoder(_analysis(fn)).encode_function("deposit")
        assert harness is not None
        assert "loc_shares" in harness["unbound_locals"]

    def test_havocked_local_emitted_into_code(self):
        fn = _fn(assignments=[
            {"op": "=", "lhs": "shares", "rhs": "assets", "order": 0,
             "when": [{"c": "i < n", "loop": True}]},
        ])
        harness = HarnessEncoder(_analysis(fn)).encode_function("deposit")
        assert "_unbound_locals = ['loc_shares']" in harness["code"]

    def test_havocked_marked_partial_and_documented(self):
        fn = _fn(assignments=[
            {"op": "=", "lhs": "shares", "rhs": "assets", "order": 0,
             "when": [{"c": "i < n", "loop": True}]},
        ])
        harness = HarnessEncoder(_analysis(fn)).encode_function("deposit")
        assert harness["quality"] == "PARTIAL"
        assert any("_unbound_locals" in a for a in harness["assumptions"])

    def test_bound_local_is_not_unbound(self):
        # Same local, but written unconditionally -> a defining equality IS
        # emitted, so it must NOT be flagged unbound.
        fn = _fn(assignments=[
            {"op": "=", "lhs": "shares", "rhs": "assets", "order": 0,
             "when": []},
        ])
        harness = HarnessEncoder(_analysis(fn)).encode_function("deposit")
        assert "loc_shares" not in harness["unbound_locals"]
        assert "_unbound_locals = []" in harness["code"]

    def test_no_locals_no_unbound(self):
        harness = HarnessEncoder(_analysis(_fn())).encode_function("deposit")
        assert harness["unbound_locals"] == []

    def test_sequence_merges_unbound(self):
        analysis = {
            "contract": "MiniVault",
            "functions": {
                "deposit(uint256)": _fn(assignments=[
                    {"op": "=", "lhs": "shares", "rhs": "assets", "order": 0,
                     "when": [{"c": "i < n", "loop": True}]}]),
                "withdraw(uint256)": _fn(
                    full_name="withdraw(uint256)",
                    assignments=[
                        {"op": "=", "lhs": "owed", "rhs": "assets", "order": 0,
                         "when": [{"c": "j < m", "loop": True}]}]),
            },
            "storage_layout": [{"name": "totalShares", "type": "uint256"}],
        }
        chain = HarnessEncoder(analysis).encode_function_sequence(
            ["deposit", "withdraw"])
        assert chain is not None
        assert "loc_shares_c1" in chain["unbound_locals"]
        assert "loc_owed_c2" in chain["unbound_locals"]
        assert chain["unbound_locals"] == sorted(set(chain["unbound_locals"]))


# ===========================================================================
# B. Z3_RUNNER — strict lint rejects vacuous proofs on havocked symbols
# ===========================================================================
HAVOCKED_HARNESS = """from z3 import *
def build_model():
    a_assets = Int('a_assets')
    l_shares = Int('l_shares')
    totalSupply = Int('totalSupply')
    totalAssets = Int('totalAssets')
    _bounds = []
    _guards = []
    _transitions = []
    _unbound_locals = ['loc_shares']
    solver = Solver()
    solver.add(_bounds + _guards + _transitions)
    V = {'arg_assets': a_assets, 'loc_shares': l_shares,
         'totalSupply': totalSupply, 'totalAssets': totalAssets}
    return solver, V
"""

# The exact shape of the real deposit_8e6273 proof.py that shipped a false
# "confirmed": it asserts V['loc_shares'] == 0 on a havocked (free) symbol.
VACUOUS_PROPERTY = """solver, V = build_model()
solver.push()
print("SANITY:", solver.check())
solver.pop()
solver.add(V['arg_assets'] > 0)
solver.add(V['totalSupply'] > 0)
solver.add(V['totalAssets'] > 0)
solver.add(V['loc_shares'] == 0)
if solver.check() == sat:
    print("BUG FOUND:", solver.model())
else:
    print("Property holds")
"""

BOUND_PROPERTY = """solver, V = build_model()
solver.push()
print("SANITY:", solver.check())
solver.pop()
solver.add(V['arg_assets'] > 0)
solver.add(V['loc_shares'] == (V['arg_assets'] * V['totalSupply']) / V['totalAssets'])
solver.add(V['loc_shares'] == 0)
if solver.check() == sat:
    print("BUG FOUND:", solver.model())
else:
    print("Property holds")
"""


class TestLintUnboundLocals:
    def test_rejects_vacuous_assertion_on_havocked_symbol(self):
        issue = z3_runner._lint_property_quality(HAVOCKED_HARNESS + VACUOUS_PROPERTY)
        assert issue is not None
        assert "HAVOCKED" in issue
        assert "loc_shares" in issue

    def test_accepts_once_symbol_is_bound(self):
        assert z3_runner._lint_property_quality(
            HAVOCKED_HARNESS + BOUND_PROPERTY) is None

    def test_backward_compatible_without_harness_list(self):
        # A standalone script with no `_unbound_locals` must never be rejected
        # by this rule, even though it asserts on a bare symbol.
        standalone = """from z3 import *
shares = Int('shares')
s = Solver()
s.push()
print("SANITY:", s.check())
s.pop()
s.add(shares == 0)
if s.check() == sat:
    print("BUG FOUND:", s.model())
else:
    print("Property holds")
"""
        assert z3_runner._lint_property_quality(standalone) is None

    def test_run_z3_strict_blocks_vacuous_before_execution(self):
        result = z3_runner.run_z3(HAVOCKED_HARNESS + VACUOUS_PROPERTY, strict=True)
        assert result["status"] == "error"
        assert "HAVOCKED" in result["error"]


class TestReferencedUnboundLocals:
    def test_referenced_key_returned(self):
        code = HAVOCKED_HARNESS + VACUOUS_PROPERTY
        assert z3_runner._referenced_unbound_locals(code) == ["loc_shares"]

    def test_unreferenced_key_ignored(self):
        code = HAVOCKED_HARNESS + """solver, V = build_model()
solver.push()
print("SANITY:", solver.check())
solver.pop()
solver.add(V['arg_assets'] > 0)
if solver.check() == sat:
    print("BUG FOUND:", solver.model())
else:
    print("Property holds")
"""
        assert z3_runner._referenced_unbound_locals(code) == []

    def test_no_harness_list_empty(self):
        assert z3_runner._referenced_unbound_locals("x = 1\n") == []


class TestHasBindingEquality:
    def test_bare_zero_assertion_is_not_a_binding(self):
        assert not z3_runner._has_binding_equality(
            "solver.add(V['loc_shares'] == 0)", "loc_shares")

    def test_arithmetic_equality_is_a_binding(self):
        code = ("solver.add(V['loc_shares'] == "
                "(V['arg_assets'] * V['totalSupply']) / V['totalAssets'])")
        assert z3_runner._has_binding_equality(code, "loc_shares")

    def test_eq_form_is_a_binding(self):
        assert z3_runner._has_binding_equality(
            "solver.add(Eq(V['loc_shares'], a_assets * totalSupply))",
            "loc_shares")

    def test_reversed_equality_is_a_binding(self):
        assert z3_runner._has_binding_equality(
            "solver.add((V['arg_assets'] * 2) == V['loc_shares'])", "loc_shares")

    def test_alias_binding(self):
        code = ("shares = V['loc_shares']\n"
                "solver.add(shares == a_assets + 1)")
        assert z3_runner._has_binding_equality(code, "loc_shares")


# ===========================================================================
# C. SCHEMA — unverified findings never claim to be vulnerabilities
# ===========================================================================
class TestDetectForcedState:
    def test_vm_store(self):
        assert detect_forced_state("vm.store(address(vault), slot, bytes32(uint(0)));")

    def test_vm_etch(self):
        assert detect_forced_state("vm.etch(target, code);")

    def test_clean_test(self):
        assert not detect_forced_state("vault.deposit(500);\nassertEq(x, y);")

    def test_empty(self):
        assert not detect_forced_state("")


class TestExtractQcReason:
    def test_extracts_reason(self):
        log = '{"status": "failed", "reason": "shares should be zero"}\ntrailing warn'
        assert extract_qc_reason(log) == "shares should be zero"

    def test_unescapes_json(self):
        log = r'{"reason": "a: \"b\" < c"}'
        assert extract_qc_reason(log) == 'a: "b" < c'

    def test_no_reason(self):
        assert extract_qc_reason('{"status": "passed"}') is None

    def test_empty(self):
        assert extract_qc_reason("") is None


def _finding(severity="high"):
    return {
        "target_function": "deposit",
        "intent": "Zero-share mint when total supply is zero allows draining",
        "constraint": "shares > 0",
        "relevant_code": "uint256 shares = (assets * totalSupply) / totalAssets;",
        "severity_guess": severity,
    }


def _state():
    return {
        "contract_name": "MiniVault",
        "z3_code": "solver, V = build_model()",
        "z3_result": {"status": "sat", "output": "BUG FOUND: []"},
        "iterations": 1,
    }


class TestBuildFindingHonesty:
    def test_harness_error_capped_to_informational(self):
        f = build_finding(_finding("high"), _state(), "fixed",
                          "vault.deposit(1);", "", "harness_error")
        assert f["severity"] == "informational"
        assert f["title"].startswith("[UNVERIFIED]")
        assert f["metadata"]["verified"] is False
        assert f["qc_status"] == "harness_error"

    def test_inconclusive_capped(self):
        f = build_finding(_finding("critical"), _state(), "fixed",
                          "", "", "inconclusive")
        assert f["severity"] == "informational"
        assert f["metadata"]["verified"] is False

    def test_confirmed_keeps_severity(self):
        f = build_finding(_finding("high"), _state(), "fixed",
                          "vault.deposit(1);", '{"reason":"ok"}', "confirmed")
        assert f["severity"] == "high"
        assert not f["title"].startswith("[UNVERIFIED]")
        assert f["metadata"]["verified"] is True

    def test_forced_state_recorded(self):
        poc = "vm.store(address(vault), slot, bytes32(uint(0)));\nvault.withdraw(1);"
        f = build_finding(_finding(), _state(), "fixed", poc, "", "confirmed")
        assert f["metadata"]["poc_forces_state"] is True

    def test_natural_poc_not_forced(self):
        f = build_finding(_finding(), _state(), "fixed",
                          "vault.deposit(500);", "", "confirmed")
        assert f["metadata"]["poc_forces_state"] is False

    def test_qc_asserted_recorded(self):
        f = build_finding(_finding(), _state(), "fixed", "",
                          '{"reason": "total assets mismatch"}', "harness_error")
        assert f["metadata"]["qc_asserted"] == "total assets mismatch"


# ===========================================================================
# D. FORMATTER — verification status is visible; unverified never looks proven
# ===========================================================================
def _report(qc, severity="high"):
    fmt = SubmissionFormatter()
    return fmt.compile_bounty_report(
        finding_idx=1, stem="MiniVault", finding=_finding(severity),
        state={"mode": "z3", "bug_report": "SAT violation"},
        fixed_code="// fixed", qc=qc)


class TestFormatterVerificationStatus:
    def test_unverified_labeled_and_capped(self):
        md = _report({"qc_status": "harness_error", "poc_test_code": "",
                      "forge_output": ""})
        assert "VERIFICATION STATUS" in md
        assert "NOT REPRODUCED" in md
        assert "[UNVERIFIED]" in md
        assert "INFORMATIONAL (UNVERIFIED)" in md

    def test_confirmed_shows_confirmed(self):
        md = _report({"qc_status": "confirmed", "poc_test_code": "",
                      "forge_output": ""})
        assert "VERIFICATION STATUS" in md
        assert "CONFIRMED" in md
        assert "[UNVERIFIED]" not in md
        # severity label stays the finding's real severity
        assert "HIGH:" in md

    def test_forced_state_disclosed(self):
        md = _report({"qc_status": "confirmed",
                      "poc_test_code": "vm.store(a, s, v);",
                      "forge_output": ""})
        assert "force-constructs" in md
        assert "natural reachability" in md.lower()

    def test_qc_assertion_surfaced(self):
        md = _report({"qc_status": "harness_error", "poc_test_code": "",
                      "forge_output": '{"reason": "div by zero unreachable"}'})
        assert "What the EVM test actually asserted" in md
        assert "div by zero unreachable" in md

    def test_no_qc_backward_compatible(self):
        md = _report(None)
        assert "VERIFICATION STATUS" not in md
        assert "[UNVERIFIED]" not in md
        assert "HIGH:" in md


# ===========================================================================
# E. INSPECTOR — same-root-cause twins merge; higher severity retained
# ===========================================================================
def _inspector():
    # deduplicate() touches no LLM, so None agents are fine.
    return Inspector(None, None)


def _twin(intent, severity="high", code="uint256 netAssets = assets - penaltyBps;",
          constraint="netAssets >= assets"):
    return {
        "target_function": "withdraw",
        "intent": intent,
        "constraint": constraint,
        "relevant_code": code,
        "severity_guess": severity,
    }


class TestDedupSameRootCause:
    def test_paraphrased_twins_on_one_line_merge(self):
        # Near-zero intent overlap, identical single-line locus -> one finding.
        a = _twin("Penalty subtracts flat basis points instead of a percentage "
                  "causing accounting drift")
        b = _twin("Underflow denial of service when assets are smaller than the "
                  "penalty value reverts")
        out = _inspector().deduplicate([a, b])
        assert len(out) == 1

    def test_merge_retains_higher_severity(self):
        low = _twin("Minor rounding drift in the penalty math path", severity="medium")
        high = _twin("Critical drain of the whole vault via penalty error",
                     severity="high")
        out = _inspector().deduplicate([low, high])
        assert len(out) == 1
        assert out[0]["severity_guess"] == "high"

    def test_merge_retains_higher_severity_reverse_order(self):
        high = _twin("Critical drain of the whole vault via penalty error",
                     severity="high")
        low = _twin("Minor rounding drift in the penalty math path", severity="medium")
        out = _inspector().deduplicate([high, low])
        assert len(out) == 1
        assert out[0]["severity_guess"] == "high"

    def test_distinct_code_not_merged(self):
        a = _twin("first unrelated issue", code="uint256 a = 1;\nuint256 b = 2;\nuint256 c = 3;")
        b = _twin("second unrelated issue", code="require(x > 0);\nrequire(y > 0);\nrequire(z > 0);")
        out = _inspector().deduplicate([a, b])
        assert len(out) == 2

    def test_different_functions_never_merge(self):
        a = _twin("same line different function")
        b = _twin("same line different function")
        b["target_function"] = "emergencyWithdraw"
        out = _inspector().deduplicate([a, b])
        assert len(out) == 2

    def test_large_identical_block_still_uses_text_similarity(self):
        # Identical code but MANY lines (>2) is not auto-merged by the tiny
        # rule; with unrelated intents AND constraints they stay distinct.
        big = "\n".join(f"uint256 v{i} = {i};" for i in range(6))
        a = _twin("alpha beta gamma delta", code=big, constraint="fooTotal >= bar")
        b = _twin("zeta theta iota kappa", code=big, constraint="bazQux <= quux")
        out = _inspector().deduplicate([a, b])
        assert len(out) == 2

    def test_ids_reassigned(self):
        a = _twin("one issue here")
        b = _twin("two issue here", code="require(a > 0);\nrequire(b > 0);\nrequire(c > 0);")
        out = _inspector().deduplicate([a, b])
        assert [f["id"] for f in out] == list(range(1, len(out) + 1))

    def test_similar_intent_overlap_still_merges(self):
        # Backward-compatible path: overlapping code + similar intent merges.
        a = _twin("the penalty subtraction underflows the vault assets balance")
        b = _twin("the penalty subtraction underflows the vault assets total")
        out = _inspector().deduplicate([a, b])
        assert len(out) == 1
