"""Targeted-MCP tests: the four audit modes (cold-full, cold-scoped,
warm-seeded, warm-scoped), the prior-finding adapter, chunk auto-wrap, and the
shared verifier-only subgraph that skips the bug hunter.

These are LLM-free: dispatch is asserted by monkeypatching the two runners, and
the pure helpers are exercised directly.
"""
import json

import pytest

from domain import pipeline
from domain.pipeline import (
    _adapt_prior_finding,
    _autowrap_contract,
    _build_seeds,
    _build_verify_graph,
    _harness_for_target,
    run_pipeline_code,
)


FULL_CONTRACT = "// SPDX-License-Identifier: MIT\npragma solidity 0.8.20;\ncontract MiniVault { function deposit(uint256 a) external {} }"
FRAGMENT = "function deposit(uint256 assets) external { require(assets > 0); }"


# ===========================================================================
# A. Auto-wrap: bare fragments become compilable, full contracts pass through
# ===========================================================================
class TestAutoWrap:
    def test_full_contract_untouched(self):
        assert _autowrap_contract(FULL_CONTRACT) == FULL_CONTRACT

    def test_fragment_wrapped_in_contract(self):
        out = _autowrap_contract(FRAGMENT)
        assert "contract GodelTarget {" in out
        assert "function deposit(uint256 assets)" in out
        assert out.rstrip().endswith("}")
        assert "pragma solidity" in out
        assert "SPDX-License-Identifier" in out

    def test_fragment_keeps_single_pragma(self):
        frag = "pragma solidity 0.8.20;\nfunction f() external {}"
        out = _autowrap_contract(frag)
        assert out.count("pragma solidity") == 1
        assert "pragma solidity 0.8.20;" in out  # original version preserved
        assert "contract GodelTarget {" in out

    def test_empty_passthrough(self):
        assert _autowrap_contract("") == ""
        assert _autowrap_contract("   ") == "   "

    def test_interface_counts_as_decl(self):
        code = "interface IERC20 { function transfer(address to, uint256 a) external returns (bool); }"
        assert _autowrap_contract(code) == code


# ===========================================================================
# B. Prior-finding adapter: OUTPUT (finding.json) -> INPUT (specifier) shape
# ===========================================================================
class TestAdaptPriorFinding:
    def test_output_shape_maps_to_input(self):
        raw = {
            "function": "deposit",
            "summary": "shares round to zero",
            "root_cause": "assets*totalSupply/totalAssets truncates",
            "invariant": "assets > 0 => shares > 0",
            "severity": "informational",
            "counterexample": {"a_assets": 1, "totalAssets": 1000},
        }
        out = _adapt_prior_finding(raw)
        assert out["target_function"] == "deposit"
        assert out["intent"] == "shares round to zero"
        assert out["constraint"] == "assets*totalSupply/totalAssets truncates"
        assert out["relevant_code"] == "assets > 0 => shares > 0"
        # informational is the demotion CAP, not the real severity -> reset
        assert out["severity_guess"] == "medium"
        assert out["counterexample"] == {"a_assets": 1, "totalAssets": 1000}

    def test_input_shape_passthrough(self):
        raw = {
            "target_function": "withdraw",
            "intent": "burns zero shares",
            "constraint": "C",
            "relevant_code": "RC",
            "severity_guess": "high",
        }
        out = _adapt_prior_finding(raw)
        assert out["target_function"] == "withdraw"
        assert out["severity_guess"] == "high"  # real severity preserved
        assert out["intent"] == "burns zero shares"

    def test_json_string_accepted(self):
        raw = {"function": "deposit", "summary": "S"}
        out = _adapt_prior_finding(json.dumps(raw))
        assert out["target_function"] == "deposit"
        assert out["intent"] == "S"

    def test_bare_string_becomes_intent(self):
        out = _adapt_prior_finding("rounding bug in deposit", target="deposit")
        assert out["intent"] == "rounding bug in deposit"
        assert out["target_function"] == "deposit"

    def test_target_fills_missing_function(self):
        out = _adapt_prior_finding({"summary": "S"}, target="emergencyWithdraw")
        assert out["target_function"] == "emergencyWithdraw"

    def test_instructions_folded_into_intent(self):
        out = _adapt_prior_finding(
            {"function": "deposit", "summary": "zero shares"},
            instructions="re-check with share price > 1",
        )
        assert "zero shares" in out["intent"]
        assert "Auditor note / hypothesis to re-confirm" in out["intent"]
        assert "re-check with share price > 1" in out["intent"]

    def test_junk_returns_none(self):
        assert _adapt_prior_finding({}) is None
        assert _adapt_prior_finding(123) is None
        assert _adapt_prior_finding("") is None
        assert _adapt_prior_finding({"severity": "high"}) is None


# ===========================================================================
# C. Seed building: list / JSON string / instructions-only synthesis
# ===========================================================================
class TestBuildSeeds:
    def test_from_list_of_findings(self):
        seeds = _build_seeds([{"function": "deposit", "summary": "S1"},
                              {"function": "withdraw", "summary": "S2"}])
        assert len(seeds) == 2
        assert {s["target_function"] for s in seeds} == {"deposit", "withdraw"}

    def test_from_json_string(self):
        seeds = _build_seeds(json.dumps([{"function": "deposit", "summary": "S"}]))
        assert len(seeds) == 1
        assert seeds[0]["target_function"] == "deposit"

    def test_instructions_only_synthesizes_seed(self):
        seeds = _build_seeds(None, instructions="small deposit mints zero shares",
                             target="deposit")
        assert len(seeds) == 1
        assert seeds[0]["target_function"] == "deposit"
        assert seeds[0]["intent"].startswith("Auditor-directed hypothesis")
        assert "small deposit mints zero shares" in seeds[0]["intent"]

    def test_nothing_yields_no_seeds(self):
        assert _build_seeds(None) == []
        assert _build_seeds([]) == []
        assert _build_seeds("") == []
        assert _build_seeds([{}, None]) == []

    def test_instructions_folded_into_each_prior_seed(self):
        seeds = _build_seeds([{"function": "deposit", "summary": "S"}],
                             instructions="global note")
        assert len(seeds) == 1
        assert "global note" in seeds[0]["intent"]


# ===========================================================================
# D. Harness selection guards (no static analysis -> degrade, never crash)
# ===========================================================================
class TestHarnessForTarget:
    def test_none_analysis(self):
        assert _harness_for_target(None, "deposit") == (None, None)

    def test_empty_target(self):
        assert _harness_for_target({}, "deposit") == (None, None)
        assert _harness_for_target({"functions": {}}, "") == (None, None)


# ===========================================================================
# E. Verifier-only subgraph enters at specifier, skips the hunter/supervisor
# ===========================================================================
class TestVerifyGraph:
    def test_nodes_exclude_discovery(self):
        compiled = _build_verify_graph()
        nodes = set(compiled.get_graph().nodes.keys())
        for expected in ("specifier", "executor", "gatekeeper", "fixer"):
            assert expected in nodes
        for forbidden in ("bug_hunter", "supervisor"):
            assert forbidden not in nodes


# ===========================================================================
# F. Dispatcher routing: which mode fires for which arguments (LLM-free)
# ===========================================================================
class TestDispatch:
    @pytest.fixture
    def record(self, monkeypatch):
        calls = {"cold": [], "warm": []}

        def fake_cold(folder, function_filter=""):
            calls["cold"].append({"folder": folder, "function_filter": function_filter})
            return ["COLD"]

        def fake_warm(contract_code, readme, seeds, target):
            calls["warm"].append({"seeds": seeds, "target": target})
            return ["WARM"]

        monkeypatch.setattr(pipeline, "run_pipeline", fake_cold)
        monkeypatch.setattr(pipeline, "run_seeded_verification", fake_warm)
        return calls

    def test_cold_full_when_no_extras(self, record):
        out = run_pipeline_code(FULL_CONTRACT)
        assert out == ["COLD"]
        assert len(record["cold"]) == 1
        assert record["cold"][0]["function_filter"] == ""
        assert record["warm"] == []

    def test_cold_scoped_passes_target(self, record):
        out = run_pipeline_code(FULL_CONTRACT, target="deposit")
        assert out == ["COLD"]
        assert record["cold"][0]["function_filter"] == "deposit"
        assert record["warm"] == []

    def test_warm_seeded_on_prior_findings(self, record):
        out = run_pipeline_code(
            FULL_CONTRACT,
            prior_findings=[{"function": "deposit", "summary": "zero shares"}],
        )
        assert out == ["WARM"]
        assert record["cold"] == []
        assert len(record["warm"]) == 1
        assert record["warm"][0]["seeds"][0]["target_function"] == "deposit"

    def test_warm_scoped_on_instructions_only(self, record):
        out = run_pipeline_code(
            FULL_CONTRACT, instructions="check zero-share minting", target="deposit")
        assert out == ["WARM"]
        assert record["cold"] == []
        assert record["warm"][0]["target"] == "deposit"
        assert len(record["warm"][0]["seeds"]) == 1

    def test_prior_findings_json_string_routes_warm(self, record):
        out = run_pipeline_code(
            FULL_CONTRACT,
            prior_findings=json.dumps({"function": "withdraw", "summary": "S"}),
        )
        assert out == ["WARM"]
        assert record["warm"][0]["seeds"][0]["target_function"] == "withdraw"

    def test_malformed_findings_degrade_to_cold(self, record):
        out = run_pipeline_code(FULL_CONTRACT, prior_findings=[{}, None, ""])
        assert out == ["COLD"]
        assert record["warm"] == []
        assert len(record["cold"]) == 1

    def test_backward_compatible_two_arg_call(self, record):
        out = run_pipeline_code(FULL_CONTRACT, "some readme")
        assert out == ["COLD"]
        assert record["cold"][0]["function_filter"] == ""
