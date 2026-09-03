"""Forge-direct seeded path (Z3-timeout rescue) tests.

When a warm-seeded finding carries a CONCRETE witness and Z3 times out on a
nonlinear property, the pipeline must NOT abandon the finding to an incomplete
artifact. It should route to the Foundry gatekeeper (EVM ground truth) and hand
the PoC generator the supplied values. These tests lock in:

  1. route_after_executor sends timeout-with-witness -> "gatekeeper"
     (and still ENDs a bare timeout with no witness to test).
  2. executor_node surfaces the witness into bug_report on that path, keeping
     the old inconclusive branch intact for witness-less timeouts.
  3. PropertyVerifierAgent.generate_test_suite folds the supplied witness into
     the PoC facts ONLY when Z3 produced no SAT witness of its own.
  4. build_finding falls back to the supplied counterexample so a
     Forge-confirmed artifact reports the real values, not an empty map.

Run with: pytest tests/test_forge_direct_seed_path.py -v
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


class MockResponse:
    def __init__(self, content="```solidity\nfunction x() public {}\n```"):
        self.content = content


class MockLLM:
    def __init__(self, response_content="OK"):
        self.last_messages = None
        self._response = MockResponse(response_content)

    def invoke(self, messages, **kwargs):
        self.last_messages = messages
        return self._response


def _get_user_content(messages) -> str:
    for msg in messages:
        if type(msg).__name__ == "HumanMessage":
            return msg.content
    return ""


_WITNESS = {"assets": 1, "totalSupply": 1, "totalAssets": 1000}
_CONTRACT = (
    "// SPDX-License-Identifier: MIT\n"
    "pragma solidity ^0.8.20;\n"
    "contract MiniVault {\n"
    "    function deposit(uint256 assets) public payable returns (uint256 shares) {}\n"
    "}\n"
)


# ---------------------------------------------------------------- ROUTER

def test_router_timeout_with_witness_routes_to_gatekeeper():
    from domain.pipeline import route_after_executor
    state = {
        "z3_result": {"status": "error", "z3_timeout": True,
                      "error": "Z3 timeout (30.0s)"},
        "executor_runs": 0,
        "findings": [{"target_function": "deposit(uint256)",
                      "counterexample": dict(_WITNESS)}],
    }
    assert route_after_executor(state) == "gatekeeper"


def test_router_timeout_without_witness_still_ends():
    from domain.pipeline import route_after_executor
    from langgraph.graph import END
    state = {
        "z3_result": {"status": "error", "z3_timeout": True,
                      "error": "Z3 timeout (30.0s)"},
        "executor_runs": 0,
        "findings": [{"target_function": "deposit(uint256)"}],
    }
    assert route_after_executor(state) == END


def test_router_timeout_with_empty_counterexample_still_ends():
    from domain.pipeline import route_after_executor
    from langgraph.graph import END
    state = {
        "z3_result": {"status": "error", "z3_timeout": True,
                      "error": "Z3 timeout (30.0s)"},
        "executor_runs": 0,
        "findings": [{"target_function": "deposit(uint256)",
                      "counterexample": None}],
    }
    assert route_after_executor(state) == END
    state["findings"][0]["counterexample"] = {}
    assert route_after_executor(state) == END


def test_router_timeout_with_witness_ignores_empty_finding_list():
    from domain.pipeline import route_after_executor
    from langgraph.graph import END
    state = {
        "z3_result": {"status": "error", "z3_timeout": True,
                      "error": "Z3 timeout (30.0s)"},
        "executor_runs": 0,
        "findings": [],
    }
    assert route_after_executor(state) == END


# ------------------------------------------------------------- EXECUTOR

def _timeout_cegis_result():
    return {"status": "error", "z3_timeout": True, "output": "",
            "error": "Z3 timeout (30.0s)", "repairs_used": 0,
            "deterministic_repairs": 0}


def _executor_timeout_state(with_witness=True):
    finding = {"target_function": "deposit(uint256)"}
    if with_witness:
        finding["counterexample"] = dict(_WITNESS)
    return {
        "z3_code": "from z3 import *",
        "iterations": 0, "executor_runs": 0,
        "current_focus_function": "deposit(uint256)",
        "semantic_harness": {"code": "",
                             "symbols": {"totalSupply": "z3sym_0",
                                         "shares": "z3sym_1"}},
        "findings": [finding],
    }


def test_executor_timeout_with_witness_builds_bug_report():
    from domain.graph_nodes import executor_node

    class _TimeoutCEGIS:
        def run_with_repair(self, z3_code, max_repairs=None, **kwargs):
            return _timeout_cegis_result()

    out = executor_node(_executor_timeout_state(with_witness=True), _TimeoutCEGIS())

    assert out["z3_result"]["z3_timeout"] is True
    report = out.get("bug_report", "")
    assert "Forge-direct rescue" in report
    assert "totalAssets=1000" in report          # supplied witness surfaced
    assert "assets=1" in report
    assert out.get("supervisor_critique") is None  # not fed back for futile repair
    msg = out["messages"][0].content
    assert "gatekeeper" in msg.lower()


def test_executor_timeout_without_witness_keeps_inconclusive():
    from domain.graph_nodes import executor_node

    class _TimeoutCEGIS:
        def run_with_repair(self, z3_code, max_repairs=None, **kwargs):
            return _timeout_cegis_result()

    out = executor_node(_executor_timeout_state(with_witness=False), _TimeoutCEGIS())

    assert out["z3_result"]["z3_timeout"] is True
    assert "bug_report" not in out
    critique = out.get("supervisor_critique", "")
    assert "INCONCLUSIVE" in critique
    assert "Z3 TIMEOUT" in critique
    assert "inconclusive" in out["messages"][0].content.lower()


# -------------------------------------------------------------- VERIFIER

def test_verifier_surfaces_supplied_witness_on_inconclusive():
    from domain.verifier import PropertyVerifierAgent

    mock = MockLLM(response_content="```solidity\ncontract T {}\n```")
    agent = PropertyVerifierAgent(mock)

    finding = {"target_function": "deposit",
               "intent": "non-zero deposit mints zero shares",
               "counterexample": dict(_WITNESS)}
    result_state = {
        "mode": "standard",
        "z3_result": {"status": "error", "z3_timeout": True},
        "bug_report": "[Z3 TIMEOUT] inconclusive",
    }

    agent.generate_test_suite(finding, result_state, _CONTRACT, "MiniVault.sol")

    user = _get_user_content(mock.last_messages)
    assert "supplied witness" in user
    assert "totalAssets=1000" in user
    assert "assets=1" in user


def test_verifier_does_not_override_sat_witness():
    from domain.verifier import PropertyVerifierAgent

    mock = MockLLM(response_content="```solidity\ncontract T {}\n```")
    agent = PropertyVerifierAgent(mock)

    finding = {"target_function": "deposit",
               "intent": "non-zero deposit mints zero shares",
               "counterexample": dict(_WITNESS)}
    result_state = {
        "mode": "standard",
        "z3_result": {
            "status": "sat",
            "output": "BUG FOUND: assets = 7, totalSupply = 3",
            "counterexample": {"assignments": {"assets": 7, "totalSupply": 3}},
        },
        "bug_report": "[Z3] Counterexample found",
    }

    agent.generate_test_suite(finding, result_state, _CONTRACT, "MiniVault.sol")

    user = _get_user_content(mock.last_messages)
    # Z3's own SAT witness is authoritative; the divergent supplied witness
    # (assets=1, totalAssets=1000) must NOT be injected as a conflicting directive.
    assert "supplied witness" not in user
    assert "assets=7" in user


# ------------------------------------------------------------ SCHEMA (build_finding)

def _minimal_state():
    return {
        "contract_name": "MiniVault",
        "z3_result": {"status": "error", "z3_timeout": True},
        "z3_code": "",
        "rag_diagnostics": {},
        "iterations": 0,
    }


def test_build_finding_falls_back_to_supplied_counterexample():
    from domain.schema import build_finding

    finding = {
        "target_function": "deposit",
        "intent": "non-zero deposit mints zero shares",
        "severity_guess": "high",
        "counterexample": dict(_WITNESS),
    }
    result = build_finding(finding, _minimal_state(),
                           fixed_code="", test_suite="", forge_output="",
                           qc_status="confirmed")
    assert result["counterexample"] == _WITNESS
    assert result["severity"] == "high"


def test_build_finding_empty_counterexample_when_none_supplied():
    from domain.schema import build_finding

    finding = {
        "target_function": "deposit",
        "intent": "non-zero deposit mints zero shares",
        "severity_guess": "medium",
    }
    result = build_finding(finding, _minimal_state(),
                           fixed_code="", test_suite="", forge_output="",
                           qc_status="confirmed")
    assert result["counterexample"] == {}


def test_build_finding_unverified_caps_severity_even_with_witness():
    from domain.schema import build_finding

    finding = {
        "target_function": "deposit",
        "intent": "non-zero deposit mints zero shares",
        "severity_guess": "high",
        "counterexample": dict(_WITNESS),
    }
    result = build_finding(finding, _minimal_state(),
                           fixed_code="", test_suite="", forge_output="",
                           qc_status="incomplete")
    # The supplied witness is still recorded (evidence honesty), but the verdict
    # is not confirmed, so severity stays informational.
    assert result["counterexample"] == _WITNESS
    assert result["severity"] == "informational"
    assert result["title"].startswith("[UNVERIFIED] ")
