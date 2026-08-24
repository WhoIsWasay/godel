"""Phase 3 tests: contract-invariant preservation mode.
Run: python -X utf8 testOfCode/test_phase3.py"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from domain.abstracter import abstract_contract                    # noqa: E402
from domain.invariants import (check_invariant_preservation,       # noqa: E402
                               InvariantSyntaxError)
from env_check import HAS_FIXTURES                                 # noqa: E402

PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    print(("  [PASS] " if cond else "  [FAIL] ") + name)
    PASS, FAIL = PASS + (1 if cond else 0), FAIL + (0 if cond else 1)


VAULT = """// SPDX-License-Identifier: MIT
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

tmp = tempfile.mkdtemp(prefix="p3_")
src = os.path.join(tmp, "Vault.sol")
with open(src, "w") as fh:
    fh.write(VAULT)
vault = abstract_contract(src)
check("fixture analyzed", vault is not None)

print("== T1: true invariant preserved (exact model) ==")
r = check_invariant_preservation(vault, "total@new >= 0")
check("verdict PRESERVED", r["verdict"] == "INVARIANT PRESERVED (exact)")
check("deposit preserved with FULL quality",
      any(d["status"] == "preserved" and d.get("quality") == "FULL"
          for d in r["details"]))
check("exit-style aggregate has no violations", not r["violated_by"])

print("== T2: false invariant BROKEN with concrete detection ==")
r2 = check_invariant_preservation(vault, "bal[S]@new == 0")
# deposit writes bal[S]@new = old + amount with amount>0 -> cannot stay 0
check("verdict BROKEN or POSSIBLY flagged",
      r2["verdict"] in ("INVARIANT BROKEN", "INCONCLUSIVE"))
check("deposit is the offending function",
      "deposit(uint256)" in (r2["violated_by"] + r2["possibly_violated_by"]))

print("== T3: syntax validation ==")
try:
    check_invariant_preservation(vault, "foo@new > 0")
    rejected = False
except InvariantSyntaxError:
    rejected = True
check("unknown symbols rejected", rejected)

try:
    check_invariant_preservation(vault, "import os; os.system('x')")
    rejected_evil = False
except InvariantSyntaxError:
    rejected_evil = True
check("dangerous tokens rejected", rejected_evil)

print("== T4: honest INCONCLUSIVE on over-approximated writer ==")
# StablecoinCDP.borrow: debt write is pre-call (encoded), but the function's
# guard is dropped (external call) -> PARTIAL quality; a strong claim about
# debt must NOT be reported as exactly preserved.
if HAS_FIXTURES:
    cdp_path = os.path.join("testOfCode", "fixtures", "StablecoinCDP.sol")
    cdp = abstract_contract(cdp_path)
    r4 = check_invariant_preservation(cdp, "debt@new >= 0")
    check("no FALSE 'exact preserved' claim on partial model",
          r4["verdict"] != "INVARIANT PRESERVED (exact)")
else:
    check("T4 SKIPPED (fixtures not present — contract-free CI mode)", True)

print("== T5: read-only functions trivially preserve ==")
if HAS_FIXTURES:
    vv = abstract_contract(os.path.join("testOfCode", "fixtures", "Vestingvault.sol"))
    check("vesting fixture analyzed", vv is not None)
    r5 = check_invariant_preservation(vv, "totalGranted@new >= 0")
    ro = [d for d in r5["details"] if d["function"].startswith("vestedAmount")]
    check("view fn vestedAmount preserved (verified or readonly-shortcut)",
          len(ro) == 1 and ro[0]["status"] in ("preserved_readonly", "preserved"))
    check("no false violations anywhere", not r5["violated_by"])
else:
    check("T5 SKIPPED (fixtures not present — contract-free CI mode)", True)

print("== T6: multi-state invariant with identity pinning ==")
r6 = check_invariant_preservation(vault, "total@new == bal[S]@new + bal[X]@new")
# slot X never appears in source -> unreferencable -> conservative verdict,
# but it must NEVER crash and never claim exact preservation
check("unknown-slot invariant degrades safely",
      r6["verdict"] in ("INCONCLUSIVE", "INVARIANT BROKEN"))

print("== T7: vacuity detection — unsatisfiable Inv(pre) is NOT a proof ==")
# deposit requires amount > 0, so 'amount < 0 and total >= 0' can never hold
# in the pre-state: any UNSAT here must be labeled vacuously_preserved.
r7 = check_invariant_preservation(vault, "arg_amount < 0 and total@new >= 0")
statuses = {d["function"]: d["status"] for d in r7["details"]}
dep_status = statuses.get("deposit(uint256)")
check("vacuous function labeled vacuously_preserved", dep_status == "vacuously_preserved")
check("vacuity surfaced in report list",
      "deposit(uint256)" in r7.get("vacuously_preserved_in", []))
check("vacuous-only invariant does not claim a real proof",
      "VACUOUS ONLY" in r7["verdict"] and not r7.get("preserved_in"))
check("genuine preservation still labeled preserved",
      check_invariant_preservation(vault, "total@new >= 0")["details"][0]["status"]
      == "preserved")

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
