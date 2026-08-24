"""Phase 2 tests: deterministic semantics + CEGIS + verdict policy.
Run: python -X utf8 testOfCode/test_phase2.py"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from domain.abstracter import abstract_contract          # noqa: E402
from domain.semantics import generate_harness, compose_script  # noqa: E402
from domain.z3_runner import run_z3                      # noqa: E402
from domain.cegis import CEGIS                           # noqa: E402
from env_check import HAS_FIXTURES                       # noqa: E402

PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    print(("  [PASS] " if cond else "  [FAIL] ") + name)
    PASS, FAIL = PASS + (1 if cond else 0), FAIL + (0 if cond else 1)


# ---------------------------------------------------------------- fixture
STRAIGHT_LINE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
contract Vault {
    uint256 public total;
    mapping(address => uint256) public bal;
    function deposit(uint256 amount) external {
        require(amount > 0);
        total += amount;
        bal[msg.sender] += amount;
    }
}
"""

tmp = tempfile.mkdtemp(prefix="p2_")
src = os.path.join(tmp, "Vault.sol")
with open(src, "w") as fh:
    fh.write(STRAIGHT_LINE)

analysis = abstract_contract(src)
harness = generate_harness(analysis, "deposit")

print("== T1: harness generation (golden structure) ==")
check("harness produced", harness is not None)
if harness:
    check("quality FULL (straight-line, no ext calls)", harness["quality"] == "FULL")
    check("build_model defined", "def build_model():" in harness["code"])
    check("state old/new pairs declared", "total__old" in harness["code"] and "total__new" in harness["code"])
    check("arg symbol declared", "a_amount" in harness["code"])
    check("guard encoded", "a_amount > 0" in harness["code"])
    check("transition equality emitted", "total__new == ((total__old) + (a_amount))" in harness["code"])

print("== T2: END-TO-END FV SMOKE — real Z3, real verdicts ==")
# T2a: true invariant -> UNSAT ("Property holds")
good_prop = """
solver, V = build_model()
solver.add(Not(V['total@new'] >= V['total']))
if solver.check() == sat:
    print("BUG FOUND:", solver.model())
else:
    print("Property holds")
"""
r1 = run_z3(compose_script(harness, good_prop))
check("invariant total_new >= total_old is UNSAT", r1["status"] == "unsat")

# T2b: false invariant ("deposit grows total by amount PLUS 1") -> SAT
bad_prop = """
solver, V = build_model()
solver.add(Not(V['total@new'] >= V['total'] + V['arg_amount'] + 1))
if solver.check() == sat:
    print("BUG FOUND:", solver.model())
else:
    print("Property holds")
"""
r2 = run_z3(compose_script(harness, bad_prop))
check("false claim total_new == old+amount is SAT", r2["status"] == "sat")
cex = CEGIS.extract_counterexample(r2.get("output") or "")
check("counterexample parsed from model output",
      isinstance(cex.get("assignments"), dict) and len(cex["assignments"]) > 0)

print("== T3: sound over-approximation on complex function ==")
if HAS_FIXTURES:
    cdp = abstract_contract(os.path.join("testOfCode", "fixtures", "StablecoinCDP.sol"))
    h_borrow = generate_harness(cdp, "borrow")
    check("borrow harness produced", h_borrow is not None)
    if h_borrow:
        check("borrow quality PARTIAL (external call / branch)", h_borrow["quality"] == "PARTIAL")
        check("unmodeled parts documented", any(
            ("external call" in u) or ("guard dropped" in u) or ("branch" in u)
            for u in h_borrow["untranslated"]))
        r3 = run_z3(compose_script(h_borrow, """
solver, V = build_model()
solver.add(Not(V['arg_borrowAmount'] >= 0))
if solver.check() == sat:
    print("BUG FOUND:", solver.model())
else:
    print("Property holds")
"""))
        check("partial harness still executes cleanly", r3["status"] in ("sat", "unsat"))
else:
    cdp = None
    check("T3 SKIPPED (fixtures not present — contract-free CI mode)", True)

print("== T4: encoder failure -> graceful NONE ==")
check("missing function -> None", generate_harness(cdp, "doesNotExist") is None)
check("None analysis -> None", generate_harness(None, "x") is None)

print("== T5: CEGIS repair loop + counterexample extraction ==")


class FakeZ3:
    def __init__(self):
        self.calls = 0

    def __call__(self, code):
        self.calls += 1
        if self.calls == 1:
            return {"status": "error", "output": None,
                    "error": "NameError: name 'totl__old' is not defined"}
        return {"status": "sat", "output": "BUG FOUND: a_amount=5, msg_sender=42",
                "error": None}


class FakeLLM:
    def invoke(self, msgs):
        class R:
            content = "```python\nfrom z3 import *\n# fixed\n```"
        return R()


fake_z3 = FakeZ3()
cegis = CEGIS(agent=FakeLLM(), run_z3_tool=fake_z3)
res = cegis.run_with_repair("broken code")
check("repair loop recovered to sat", res["status"] == "sat")
check("exactly one repair used", res.get("repairs_used") == 1)
check("structured counterexample extracted",
      res["counterexample"]["assignments"].get("a_amount") == 5)

cegis_fail = CEGIS(agent=FakeLLM(), run_z3_tool=lambda c: {
    "status": "error", "output": None, "error": "boom"})
res2 = cegis_fail.run_with_repair("bad", max_repairs=1)
check("unrepairable error stays error (no crash)", res2["status"] == "error")

print("== T6: honest verdict labels ==")
from domain.pipeline import _classify_terminal_state  # noqa: E402

base = {"verified_bugs": [], "findings": [], "supervisor_runs": 0,
        "supervisor_critique": None, "executor_runs": 1,
        "z3_result": {"status": "unsat"}}
v_full = _classify_terminal_state({**base, "model_quality": "FULL"})
v_part = _classify_terminal_state({**base, "model_quality": "PARTIAL"})
v_none = _classify_terminal_state(base)
check("FULL label exact-model claim", "exact deterministic" in v_full)
check("PARTIAL label over-approximation claim", "over-approximated" in v_part)
check("no-harness keeps legacy label", "mathematically safe" in v_none)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
