"""Targeted-MCP tests: the four audit modes (cold-full, cold-scoped,
warm-seeded, warm-scoped), the prior-finding adapter, chunk auto-wrap, and the
shared verifier-only subgraph that skips the bug hunter.

These are LLM-free: dispatch is asserted by monkeypatching the two runners, and
the pure helpers are exercised directly.
"""
import json

import pytest

from domain import pipeline
from domain import config, rag
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

    # --- Regression: the seeded subgraph must TERMINATE, not recurse forever ---
    # opencode hit an abort that surfaced as analysis_incomplete / iterations=0:
    # the specifier returned empty z3_code and the graph spun an unbounded loop
    # stopped only by GraphRecursionError. Two variants, both LLM-free — only
    # node_specifier is mocked (a 1-arg callable, matching how LangGraph invokes
    # a node). node_executor stays REAL in Variant 2 so its bounded empty-code
    # path is exercised; it early-returns before touching `cegis`, so no
    # network/LLM cost. recursion_limit is set well ABOVE the natural termination
    # to prove the graph RETURNS on its own rather than being cut off.

    SEED = {"target_function": "deposit", "severity_guess": "medium",
            "intent": "assets>0 => shares>0 (Anti-Dilution)",
            "constraint": "shares = (assets*totalSupply)/totalAssets",
            "relevant_code": "function deposit(uint256 assets) external {}"}

    def _seed_state(self):
        return pipeline._build_seed_state(
            dict(self.SEED), "contract MiniVault {}", "MiniVault", "",
            {"contract": "MiniVault", "functions": []},
            harness=None, chain_harness=None)

    def test_supervisor_alert_terminates_at_end(self, monkeypatch):
        # Variant 1: [SUPERVISOR_ALERT] -> route_after_specifier returns
        # "supervisor". The verify graph has no supervisor, so that route must map
        # to END (honest incomplete) instead of aliasing back to "specifier".
        monkeypatch.setattr(
            pipeline, "node_specifier",
            lambda state: {"supervisor_critique": "[SUPERVISOR_ALERT] cannot express",
                           "z3_code": "", "messages": []})
        compiled = _build_verify_graph()
        final = compiled.invoke(self._seed_state(), config={"recursion_limit": 25})
        assert final.get("executor_runs", 0) == 0          # executor never reached
        assert (final.get("z3_result") or {}).get("status") is None
        assert len(final.get("findings") or []) == 1       # seed left queued
        assert pipeline._should_flag_incomplete(final)     # honest incomplete artifact

    def test_blank_z3_code_terminates_at_executor_bound(self, monkeypatch):
        # Variant 2: blank z3_code with no alert -> executor early-return must set
        # z3_result status + increment executor_runs so route_after_executor's
        # EXECUTOR_MAX_ITERATIONS bound ends the loop (was unbounded before).
        monkeypatch.setattr(
            pipeline, "node_specifier",
            lambda state: {"z3_code": "", "messages": []})
        compiled = _build_verify_graph()
        final = compiled.invoke(self._seed_state(), config={"recursion_limit": 50})
        assert final.get("executor_runs") == config.EXECUTOR_MAX_ITERATIONS
        assert (final.get("z3_result") or {}).get("status") == "error"
        assert len(final.get("findings") or []) == 1
        assert pipeline._should_flag_incomplete(final)


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


# ===========================================================================
# G. RAG disable flag: MCP skips the ~26s model warmup + retrieval entirely
# ===========================================================================
class TestRagDisableFlag:
    def test_enabled_by_default(self, monkeypatch):
        monkeypatch.delenv("GODEL_DISABLE_RAG", raising=False)
        assert config.rag_enabled() is True

    @pytest.mark.parametrize("val", ["1", "true", "True"])
    def test_disabled_values(self, monkeypatch, val):
        monkeypatch.setenv("GODEL_DISABLE_RAG", val)
        assert config.rag_enabled() is False

    def test_zero_keeps_rag_on(self, monkeypatch):
        monkeypatch.setenv("GODEL_DISABLE_RAG", "0")
        assert config.rag_enabled() is True

    def test_warmup_skipped_when_disabled(self, monkeypatch):
        monkeypatch.setenv("GODEL_DISABLE_RAG", "1")
        import Infrastructure.postgres as pg
        calls = {"ce": 0, "embed": 0}
        monkeypatch.setattr(pg, "_get_cross_encoder",
                            lambda: calls.__setitem__("ce", calls["ce"] + 1))
        monkeypatch.setattr(pg, "embed",
                            lambda t: calls.__setitem__("embed", calls["embed"] + 1))
        pg.warmup_rag()
        assert calls == {"ce": 0, "embed": 0}

    def test_warmup_runs_when_enabled(self, monkeypatch):
        monkeypatch.delenv("GODEL_DISABLE_RAG", raising=False)
        import Infrastructure.postgres as pg
        calls = {"ce": 0, "embed": 0}
        monkeypatch.setattr(pg, "_get_cross_encoder",
                            lambda: calls.__setitem__("ce", calls["ce"] + 1))
        monkeypatch.setattr(pg, "embed",
                            lambda t: calls.__setitem__("embed", calls["embed"] + 1))
        pg.warmup_rag()
        assert calls["ce"] == 1 and calls["embed"] == 1

    def test_specifier_retrieval_short_circuits(self, monkeypatch):
        monkeypatch.setenv("GODEL_DISABLE_RAG", "1")
        findings, diag = rag.retrieve_findings_for_specifier({"target_function": "deposit"})
        assert findings == []
        assert diag.get("disabled") == "GODEL_DISABLE_RAG"

    def test_hunter_retrieval_short_circuits(self, monkeypatch):
        monkeypatch.setenv("GODEL_DISABLE_RAG", "1")
        findings, diag = rag.retrieve_findings_for_hunter("deposit", "contract X {}")
        assert findings == []
        assert diag.get("disabled") == "GODEL_DISABLE_RAG"


# ===========================================================================
# H. Seeded dry-run safety: the verify graph enters at specifier (NOT dry-
#    mocked), so dry-run must short-circuit before invoke or it makes LIVE
#    LLM calls. Regression guard for the warm-seeded MCP path.
# ===========================================================================
class TestSeededDryRun:
    SEED = {"target_function": "deposit", "severity_guess": "medium",
            "intent": "zero-share mint", "constraint": "", "relevant_code": ""}

    class FakeCompiled:
        def __init__(self, counter):
            self._counter = counter

        def get_graph(self):
            class G:
                nodes = {"__start__", "__end__", "specifier", "executor",
                         "gatekeeper", "fixer"}
            return G()

        def invoke(self, state):
            self._counter["n"] += 1
            return {**state, "verified_bugs": [], "z3_result": {"status": "unsat"},
                    "current_focus_function": "deposit"}

    def test_dry_run_does_not_invoke_graph(self, monkeypatch):
        monkeypatch.setenv("GODEL_DRY_RUN", "1")
        monkeypatch.setenv("GODEL_DISABLE_RAG", "1")
        counter = {"n": 0}
        monkeypatch.setattr(pipeline, "_build_verify_graph",
                            lambda: self.FakeCompiled(counter))
        res = pipeline.run_seeded_verification(
            FULL_CONTRACT, "", seeds=[dict(self.SEED)], target="deposit")
        assert counter["n"] == 0, "dry-run MUST NOT invoke the verify graph (live LLM calls)"
        assert len(res) == 1
        assert res[0]["qc_status"] == "dry_run_plumbing"
        assert res[0]["metadata"]["source"] == "mcp_seeded"

    def test_live_run_invokes_graph(self, monkeypatch):
        monkeypatch.delenv("GODEL_DRY_RUN", raising=False)
        monkeypatch.setenv("GODEL_DISABLE_RAG", "1")
        counter = {"n": 0}
        monkeypatch.setattr(pipeline, "_build_verify_graph",
                            lambda: self.FakeCompiled(counter))
        # Keep it hermetic/fast: no slither, no ollama, no harness, no collector.
        monkeypatch.setattr(pipeline, "abstract_contract",
                            lambda p: {"contract": "MiniVault", "functions": []})
        monkeypatch.setattr(pipeline, "warmup_rag", lambda: None)
        monkeypatch.setattr(pipeline, "_harness_for_target", lambda sa, t: (None, None))
        monkeypatch.setattr(pipeline, "_collect_state_result",
                            lambda fs, stem, results: None)
        pipeline.run_seeded_verification(
            FULL_CONTRACT, "", seeds=[dict(self.SEED)], target="deposit")
        assert counter["n"] == 1, "a live run MUST invoke the verify graph"
