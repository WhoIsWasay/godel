"""Invariant-discovery loop tests (LLM mocked — CI-safe).
Run: python -X utf8 testOfCode/test_discovery.py"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from domain.abstracter import abstract_contract   # noqa: E402
from domain.discovery import discover_invariants  # noqa: E402

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

tmp = tempfile.mkdtemp(prefix="disc_")
p = os.path.join(tmp, "Vault.sol")
with open(p, "w", encoding="utf-8") as fh:
    fh.write(VAULT)
analysis = abstract_contract(p)
check("fixture analyzed", analysis is not None)


class FakeResp:
    def __init__(self, content):
        self.content = content


class FakeLLM:
    """Returns canned JSON regardless of prompt — the point is that the
    machine-verification layer must classify correctly around it."""

    def __init__(self, payload):
        self.payload = payload
        self.calls = 0

    def invoke(self, msgs):
        self.calls += 1
        import json as _j
        return FakeResp(_j.dumps(self.payload))


# Case matrix: proven / broken / unknown-symbol rejection / duplicate.
payload = {"invariants": [
    "total@new >= 0",            # should be PROVEN
    "total@new >= total",        # conservation: PROVEN (deposit only adds)
    "bal[S]@new == 0",           # FALSE for deposit -> BROKEN with cex
    "mystery@new > 0",           # unknown symbol -> rejected
    "total@new >= 0",            # duplicate -> dropped silently
]}
llm = FakeLLM(payload)
result = discover_invariants(analysis, llm)

print(f"   proven={[p['invariant'] for p in result['proven']]}")
print(f"   broken={[(b['invariant'], b['violated_by']) for b in result['broken']]}")
print(f"   rejected={[(r['invariant'], r['reason'][:40]) for r in result['rejected']]}")

proven_set = {p["invariant"] for p in result["proven"]}
check("conservation invariant PROVEN", "total@new >= total" in proven_set)
check("trivial bound PROVEN", "total@new >= 0" in proven_set)
check("false invariant BROKEN", len(result["broken"]) == 1
      and result["broken"][0]["invariant"] == "bal[S]@new == 0")
b0 = result["broken"][0]
check("broken carries violating function", b0["violated_by"] == ["deposit(uint256)"])
cexs = b0.get("counterexamples") or []
check("broken carries machine counterexample",
      cexs and cexs[0]["function"] == "deposit(uint256)"
      and isinstance(cexs[0]["assignments"], dict))
check("unknown-symbol proposal REJECTED before solving",
      any("mystery" in r["invariant"] for r in result["rejected"]))
check("duplicate proposals deduped",
      sum(1 for p in result["proven"] if p["invariant"] == "total@new >= 0") == 1)
check("exactly one LLM call used", llm.calls == 1)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
