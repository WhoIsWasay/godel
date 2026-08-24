"""Phase 1 abstracter-layer tests. Run: python testOfCode/test_abstracter.py"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from domain.abstracter import abstract_contract, render_cfg_slice  # noqa: E402
from env_check import HAS_FIXTURES                                 # noqa: E402

PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    print(("  [PASS] " if cond else "  [FAIL] ") + name)
    PASS, FAIL = PASS + (1 if cond else 0), FAIL + (0 if cond else 1)


print("== T1: golden CFG values on fixtures/StablecoinCDP.sol ==")
a = None
if HAS_FIXTURES:
    a = abstract_contract(os.path.join("testOfCode", "fixtures", "StablecoinCDP.sol"))
    check("analysis produced", a is not None)
    f = a["functions"].get("depositCollateral(uint256)")
    check("depositCollateral present", f is not None)
    if f:
        check("nodes == 11", f["nodes"] == 11)
        check("edges == 10", f["edges"] == 10)
        check("writes == {totalCollateral,totalSupply,vaultShares}",
              set(f["state_writes"]) == {"totalCollateral", "totalSupply", "vaultShares"})
        check("external call transferFrom captured",
              any("transferFrom" in c for c in f["external_calls"]))
else:
    check("T1 SKIPPED (fixtures not present — contract-free CI mode)", True)

print("== T2: detector machinery fires on known-vulnerable synthetic ==")
code = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
contract Reentrant {
    mapping(address => uint256) public balances;
    constructor() payable {}
    function withdraw() public {
        uint256 amt = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amt}('');
        require(ok);
        balances[msg.sender] = 0;
    }
}
"""
tmp = tempfile.mkdtemp(prefix="abst_t2_")
p = os.path.join(tmp, "Vuln.sol")
with open(p, "w") as fh:
    fh.write(code)
a2 = abstract_contract(p)
checks = [(d["check"], d["impact"]) for d in a2["detectors"]]
check("reentrancy-eth HIGH detected", ("reentrancy-eth", "HIGH") in checks)
slice_txt = render_cfg_slice(a2, "withdraw")
check("slice contains detector signal", "<signal" in slice_txt and "reentrancy-eth" in slice_txt)

print("== T3: graceful degradation ==")
bad = os.path.join(tmp, "Broken.sol")
with open(bad, "w") as fh:
    fh.write("this is not solidity at all {{{")
a3 = abstract_contract(bad)
check("broken contract -> None (no crash)", a3 is None)
check("render with None -> empty string", render_cfg_slice(None, "x") == "")
check("unknown focus fn -> empty string", render_cfg_slice(a, "doesNotExist") == "")

print("== T4: focus slicing + callee expansion + token cap ==")
if HAS_FIXTURES:
    s = render_cfg_slice(a, "borrow")
    check("focus tag present", "focus_function_cfg" in s and 'signature="borrow(uint256)"' in s)
    check("storage writes surfaced", "<storage_writes>debt, lastInterestTime</storage_writes>" in s)
    tiny = render_cfg_slice(a, "borrow", max_chars=120)
    check("token cap enforced + truncation marker", len(tiny) <= 120 and "truncated" in tiny)
else:
    check("T4 SKIPPED (fixtures not present — contract-free CI mode)", True)

print("== T5: cache correctness ==")
if HAS_FIXTURES:
    a5 = abstract_contract(os.path.join("testOfCode", "fixtures", "StablecoinCDP.sol"))
    a6 = abstract_contract(os.path.join("testOfCode", "fixtures", "StablecoinCDP.sol"))
    check("cached result identity", a5 is a6)
else:
    check("T5 SKIPPED (fixtures not present — contract-free CI mode)", True)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
