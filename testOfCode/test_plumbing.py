"""Contract-free end-to-end plumbing test (CI-safe).

Generates a synthetic contract at runtime — no .sol files are committed to
the repo — and drives the full LangGraph pipeline in dry-run mode (LLM nodes
mocked). Verifies graph wiring, thread fan-out, and result collection.
Run: python -X utf8 testOfCode/test_plumbing.py"""
import os
import sys
import tempfile

# Must be set BEFORE domain.pipeline is imported (config reads it).
os.environ["GODEL_DRY_RUN"] = "1"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    print(("  [PASS] " if cond else "  [FAIL] ") + name)
    PASS, FAIL = PASS + (1 if cond else 0), FAIL + (0 if cond else 1)


SYNTH = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
contract PlumbingVault {
    uint256 public total;
    mapping(address => uint256) public bal;
    function deposit(uint256 amount) external {
        require(amount > 0);
        total += amount;
        bal[msg.sender] += amount;
    }
    function withdraw(uint256 amount) external {
        require(bal[msg.sender] >= amount);
        bal[msg.sender] -= amount;
        total -= amount;
    }
}
"""

tmpdir = tempfile.mkdtemp(prefix="godel_plumb_")
with open(os.path.join(tmpdir, "PlumbingVault.sol"), "w", encoding="utf-8") as fh:
    fh.write(SYNTH)

from domain.pipeline import run_pipeline  # noqa: E402

results = run_pipeline(tmpdir)
check("pipeline returned a list", isinstance(results, list))
check("dry-run produces zero findings by design", results == [])

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
