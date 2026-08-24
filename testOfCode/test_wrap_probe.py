"""BitVec-256 wraparound probe tests. Contract-free CI-safe.
Run: python -X utf8 testOfCode/test_wrap_probe.py"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from domain.abstracter import abstract_contract     # noqa: E402
from domain.wrap_probe import probe_contract        # noqa: E402

PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    print(("  [PASS] " if cond else "  [FAIL] ") + name)
    PASS, FAIL = PASS + (1 if cond else 0), FAIL + (0 if cond else 1)


CONTRACT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
contract WrapVault {
    uint256 public total;
    uint256 public fixedFee;
    mapping(address => uint256) public bal;

    function deposit(uint256 amount) external {
        require(amount > 0);
        total += amount;          // WRAPPABLE (no upper bound anywhere)
        bal[msg.sender] += amount;
    }
    function setFee(uint256 newFee) external {
        require(newFee <= 100);
        fixedFee = newFee;        // plain '=' no arithmetic -> not probed
    }
}
"""

tmp = tempfile.mkdtemp(prefix="wrap_")
p = os.path.join(tmp, "WrapVault.sol")
with open(p, "w", encoding="utf-8") as fh:
    fh.write(CONTRACT)

analysis = abstract_contract(p)
check("analysis produced", analysis is not None)

rows = probe_contract(analysis)
print("   rows:", [(r["function"], r["write"], r["wrap_reachable"]) for r in rows])

by = {}
for r in rows:
    by.setdefault(r["write"].split()[0], []).append(r)

check("total += amount flagged WRAPPABLE",
      any(r["wrap_reachable"] for r in by.get("total", [])))
check("bal slot += amount flagged WRAPPABLE",
      any(r["wrap_reachable"] and r["write"].startswith("bal[")
          for r in rows))
check("plain '=' assignment (fixedFee) NOT probed",
      all(not r["write"].startswith("fixedFee") for r in rows))
check("all rows carry a real z3 verdict status",
      all(r["verdict_status"] in ("sat", "unsat") for r in rows))

# '-' underflow detection
SUB = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
contract Sub {
    uint256 public stock;
    function take(uint256 n) external { stock -= n; }
}
"""
p2 = os.path.join(tmp, "Sub.sol")
with open(p2, "w", encoding="utf-8") as fh:
    fh.write(SUB)
rows2 = probe_contract(abstract_contract(p2))
check("stock -= n underflow detected",
      len(rows2) == 1 and rows2[0]["wrap_reachable"])

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
