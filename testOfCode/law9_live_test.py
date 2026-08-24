"""Law 9 LIVE e2e: multi-transaction PoC generation -> Foundry confirmation.

Exercises the real path: crafted finding + Z3 counterexample ->
PropertyVerifierAgent.generate_test_suite() (Law 9 explicit exploit sequence)
-> FoundryGatekeeper.execute_qc_validation(). Requires DEEPSEEK_API_KEY and
forge; otherwise SKIPS cleanly (exit 0) so CI stays green.

Run: python -X utf8 testOfCode/law9_live_test.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(ROOT, ".env"))

KEY = os.environ.get("DEEPSEEK_API_KEY", "").strip()
from domain.config import FORGE_BIN  # noqa: E402
FORGE_OK = os.path.exists(FORGE_BIN) or FORGE_BIN != "forge"

if not KEY or not FORGE_OK:
    print("SKIP: DEEPSEEK_API_KEY or forge not available — Law 9 live test "
          "is opt-in on dev machines only.")
    sys.exit(0)

# --- Fixture: classic reentrancy vault (multi-tx: deposit then reenter withdraw)
VULN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
contract ReentrantVault {
    mapping(address => uint256) public balances;

    constructor() payable {}

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }
}
"""

FINDING = {
    "intent": ("Reentrancy: external call transfers ETH before balance update; "
               "attacker re-enters withdraw in the callback and drains more "
               "than deposited across multiple transactions."),
    "target_function": "withdraw(uint256)",
    "severity_guess": "high",
    "constraint": "balances must be decremented before any external call",
    "relevant_code": ('(bool ok, ) = msg.sender.call{value: amount}(""); '
                      "balances[msg.sender] -= amount;"),
}

STATE = {
    "mode": "standard",
    "z3_result": {
        "status": "sat",
        "output": "BUG FOUND: a_amount=1000000000000000000",
    },
    "counterexample": {"assignments": {"a_amount": 10**18}},
}

from langchain_openai import ChatOpenAI                     # noqa: E402
from domain.verifier import PropertyVerifierAgent           # noqa: E402
from domain.gatekeeper import FoundryGatekeeper             # noqa: E402

llm = ChatOpenAI(
    model=os.environ.get("GODEL_ISOLATOR_MODEL") or "deepseek-v4-flash",
    openai_api_key=KEY,
    temperature=0.0,
    max_tokens=8000,
    openai_api_base="https://api.deepseek.com",
    extra_body={"thinking": {"type": "disabled"}},
    timeout=240,
    max_retries=2,
)

verifier = PropertyVerifierAgent(agent_llm=llm)
gatekeeper = FoundryGatekeeper(project_root=ROOT)

src_path = gatekeeper.materialize_source(VULN, "ReentrantVault")
try:
    print("== Law 9 live: generating multi-tx PoC suite ==")
    code = verifier.generate_test_suite(
        FINDING, STATE,
        contract_code=VULN,
        contract_filename=os.path.basename(src_path),
    )
    if not code.strip():
        print("FAIL: empty PoC generated")
        sys.exit(1)

    print("== Running Foundry validation ==")
    status, output = gatekeeper.execute_qc_validation(code, debug_tag="law9_live")
    print(f"   qc_status={status}")

    ok = status == "confirmed"
    print(f"\nRESULT: {'PASS — reentrancy confirmed via LLM-generated multi-tx PoC' if ok else 'FAIL'}")
    if not ok:
        tail = "\n".join((output or "").splitlines()[-25:])
        print("---- forge tail ----\n" + tail)
    sys.exit(0 if ok else 1)
finally:
    gatekeeper.cleanup_source(src_path)
