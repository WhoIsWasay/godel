"""Offline regression tests for the JSON-parsing + silent-drop hardening pass.

Zero API calls, zero forge, zero Slither. Covers:
  1. domain.json_extract — robust extraction + content-preserving repair.
  2. domain.inspector.extract_json — always returns a dict, never crashes.
  3. domain.graph_nodes._parse_hunter_output — recovery + provider_empty.
  4. domain.graph_nodes._parse_supervisor_decision — no silent approval.
  5. domain.checkpoint — atomic save, corrupt-latest fallback, msg merge.
  6. domain.graph_nodes.executor_node — critique clearing + vacuous-UNSAT.
  7. domain.pipeline._run_compositor_phase — malformed-payload guards.
  8. domain.extractor — negative counterexample values.
  9. domain.llm_utils.content_to_text — block-structured content.
 10. domain.graph_nodes.gatekeeper_node — out-of-scope clears critique.
"""
import os
import tempfile

import pytest


# ===========================================================================
# 1. json_extract — extraction
# ===========================================================================

class TestExtractJsonValue:
    def test_clean_object(self):
        from domain.json_extract import extract_json_value
        v, err = extract_json_value('{"findings": [{"severity": "high"}]}')
        assert err is None
        assert v == {"findings": [{"severity": "high"}]}

    def test_fenced_json_block(self):
        from domain.json_extract import extract_json_value
        raw = '```json\n{"findings": []}\n```'
        v, err = extract_json_value(raw)
        assert err is None
        assert v == {"findings": []}

    def test_uppercase_fence(self):
        from domain.json_extract import extract_json_value
        raw = '```JSON\n{"findings": [{"x": 1}]}\n```'
        v, err = extract_json_value(raw)
        assert err is None
        assert v == {"findings": [{"x": 1}]}

    def test_prose_around_payload(self):
        from domain.json_extract import extract_json_value
        raw = 'Sure! Here is the analysis:\n{"findings": [{"y": 2}]}\nDone.'
        v, err = extract_json_value(raw)
        assert err is None
        assert v == {"findings": [{"y": 2}]}

    def test_backticks_inside_string_value(self):
        """The killer case: a finding quotes Solidity that contains ``` ."""
        from domain.json_extract import extract_json_value
        raw = '{"findings": [{"intent": "see ```solidity code``` here", "id": 1}]}'
        v, err = extract_json_value(raw)
        assert err is None
        assert v["findings"][0]["id"] == 1
        assert "```solidity code```" in v["findings"][0]["intent"]

    def test_bare_list_wraps_to_findings_shape_at_inspector(self):
        """extract_json_value returns the raw list; inspector wraps it."""
        from domain.json_extract import extract_json_value
        v, err = extract_json_value('[{"a": 1}, {"b": 2}]')
        assert err is None
        assert v == [{"a": 1}, {"b": 2}]

    def test_garbage_returns_none(self):
        from domain.json_extract import extract_json_value
        v, err = extract_json_value("this is not json at all")
        assert v is None
        assert err

    def test_empty_returns_none(self):
        from domain.json_extract import extract_json_value
        v, err = extract_json_value("")
        assert v is None
        assert err
        v, err = extract_json_value(None)
        assert v is None
        assert err

    def test_truncated_mid_value_string(self):
        """max_tokens cutoff inside a string value must be repaired, not dropped."""
        from domain.json_extract import extract_json_value
        raw = '{"findings": [{"intent": "drain the pool by flash-loan'  # no close
        v, err = extract_json_value(raw)
        assert err is None
        assert v["findings"][0]["intent"].startswith("drain the pool")

    def test_truncated_dangling_member(self):
        """Cutoff right after a colon (, "key": ) must drop ONE member, not fail."""
        from domain.json_extract import extract_json_value
        raw = '{"findings": [{"id": 1}], "extra":'
        v, err = extract_json_value(raw)
        assert err is None
        assert v["findings"] == [{"id": 1}]


class TestRepairTruncatedJson:
    def test_closes_open_string_and_containers(self):
        from domain.json_extract import repair_truncated_json
        out = repair_truncated_json('{"findings": [{"intent": "abc')
        assert out == {"findings": [{"intent": "abc"}]}

    def test_drops_single_dangling_member(self):
        from domain.json_extract import repair_truncated_json
        out = repair_truncated_json('{"a": 1, "b":')
        assert out == {"a": 1}

    def test_complete_json_passes_through(self):
        from domain.json_extract import repair_truncated_json
        assert repair_truncated_json('{"a": [1, 2]}') == {"a": [1, 2]}

    def test_unrepairable_returns_none(self):
        from domain.json_extract import repair_truncated_json
        assert repair_truncated_json("totally not json") is None


# ===========================================================================
# 2. inspector.extract_json contract
# ===========================================================================

class TestInspectorExtractJson:
    def _inspector(self):
        # Bypass __init__ (which reads prompt files); extract_json is pure.
        from domain.inspector import Inspector
        return Inspector.__new__(Inspector)

    def test_valid_object(self):
        ins = self._inspector()
        assert ins.extract_json('{"findings": [{"id": 1}]}') == {"findings": [{"id": 1}]}

    def test_bare_list_wrapped(self):
        ins = self._inspector()
        out = ins.extract_json('[{"id": 1}]')
        assert out == {"findings": [{"id": 1}]}

    def test_unparseable_degrades_to_empty_findings(self):
        ins = self._inspector()
        out = ins.extract_json("no json here")
        assert out == {"findings": []}

    def test_scalar_degrades_to_empty_findings(self):
        ins = self._inspector()
        out = ins.extract_json("42")
        assert out == {"findings": []}


# ===========================================================================
# 3. _parse_hunter_output recovery + provider_empty
# ===========================================================================

class TestParseHunterOutputRecovery:
    def test_backticks_in_string_still_extracted(self):
        from domain.graph_nodes import _parse_hunter_output
        raw = '{"findings": [{"intent": "uses ``` fence", "id": 3}]}'
        findings, err, empty = _parse_hunter_output(raw, None)
        assert len(findings) == 1
        assert err is None
        assert empty is False

    def test_truncated_response_recovers_findings(self):
        from domain.graph_nodes import _parse_hunter_output
        raw = '{"findings": [{"id": 1, "intent": "reentrancy drain via callback'
        findings, err, empty = _parse_hunter_output(raw, None)
        assert len(findings) == 1
        assert findings[0]["id"] == 1
        assert empty is False

    def test_non_list_findings_flagged_as_parse_error(self):
        from domain.graph_nodes import _parse_hunter_output
        raw = '{"findings": {"not": "a list"}}'
        findings, err, empty = _parse_hunter_output(raw, None)
        assert findings == []
        assert err is not None
        assert empty is False

    def test_non_dict_findings_filtered(self):
        from domain.graph_nodes import _parse_hunter_output
        raw = '{"findings": [{"id": 1}, "junk", 42, {"id": 2}]}'
        findings, err, empty = _parse_hunter_output(raw, None)
        assert [f["id"] for f in findings] == [1, 2]
        assert err is None

    def test_empty_fence_only_is_provider_empty(self):
        from domain.graph_nodes import _parse_hunter_output
        raw = '```json\n```'
        findings, err, empty = _parse_hunter_output(raw, None)
        assert findings == []
        assert empty is True


# ===========================================================================
# 4. _parse_supervisor_decision
# ===========================================================================

class TestParseSupervisorDecision:
    def test_valid_object(self):
        from domain.graph_nodes import _parse_supervisor_decision
        d = _parse_supervisor_decision('{"status": "APPROVED"}')
        assert d == {"status": "APPROVED"}

    def test_think_stripped(self):
        from domain.graph_nodes import _parse_supervisor_decision
        d = _parse_supervisor_decision('<think>reasoning</think>{"status": "REJECTED"}')
        assert d == {"status": "REJECTED"}

    def test_list_wrapped_unwrapped(self):
        from domain.graph_nodes import _parse_supervisor_decision
        d = _parse_supervisor_decision('[{"status": "APPROVED"}]')
        assert d == {"status": "APPROVED"}

    def test_scalar_raises(self):
        from domain.graph_nodes import _parse_supervisor_decision
        with pytest.raises(ValueError):
            _parse_supervisor_decision('"just a string"')

    def test_no_json_raises(self):
        from domain.graph_nodes import _parse_supervisor_decision
        with pytest.raises(ValueError):
            _parse_supervisor_decision("I approve this, looks fine to me.")


# ===========================================================================
# 5. checkpoint hardening
# ===========================================================================

class TestCheckpointHardening:
    def test_corrupt_latest_falls_back_to_numbered(self):
        from domain.checkpoint import FileCheckpointer
        with tempfile.TemporaryDirectory() as tmp:
            ckpt = FileCheckpointer(tmp)
            ckpt.save({"next_agent": "a", "messages": []}, node_name="n", step=0)
            ckpt.save({"next_agent": "b", "messages": []}, node_name="n", step=1)
            # Corrupt the latest.json tag (simulates crash between writes).
            with open(os.path.join(tmp, "latest.json"), "w") as f:
                f.write("{not valid json")
            latest = ckpt.load_latest()
            assert latest is not None
            assert latest["state"]["next_agent"] == "b"

    def test_missing_latest_falls_back_to_numbered(self):
        from domain.checkpoint import FileCheckpointer
        with tempfile.TemporaryDirectory() as tmp:
            ckpt = FileCheckpointer(tmp)
            ckpt.save({"next_agent": "x", "messages": []}, node_name="n", step=0)
            os.remove(os.path.join(tmp, "latest.json"))
            latest = ckpt.load_latest()
            assert latest is not None
            assert latest["state"]["next_agent"] == "x"

    def test_atomic_write_leaves_no_tmp(self):
        from domain.checkpoint import FileCheckpointer
        with tempfile.TemporaryDirectory() as tmp:
            ckpt = FileCheckpointer(tmp)
            ckpt.save({"messages": []}, node_name="n", step=0)
            leftovers = [f for f in os.listdir(tmp) if f.endswith(".tmp")]
            assert leftovers == []

    def test_wrapper_appends_messages_not_overwrites(self):
        """The messages channel has an append reducer; the snapshot must
        append a node's new messages, not replace history with them."""
        from langchain_core.messages import HumanMessage, AIMessage
        from domain.checkpoint import FileCheckpointer, wrap_nodes_with_file_checkpointer, _deserialize_state

        with tempfile.TemporaryDirectory() as tmp:
            ckpt = FileCheckpointer(tmp)

            def node(state):
                return {"messages": [AIMessage(content="new")]}

            wrapped = wrap_nodes_with_file_checkpointer({"n": node}, ckpt)
            state = {"messages": [HumanMessage(content="old")], "next_agent": "n"}
            wrapped["n"](state)

            restored = _deserialize_state(ckpt.load_latest()["state"])
            contents = [m.content for m in restored["messages"]]
            assert contents == ["old", "new"]

    def test_wrapper_monotonic_steps(self):
        from domain.checkpoint import FileCheckpointer, wrap_nodes_with_file_checkpointer
        with tempfile.TemporaryDirectory() as tmp:
            ckpt = FileCheckpointer(tmp)
            wrapped = wrap_nodes_with_file_checkpointer(
                {"a": lambda s: {}, "b": lambda s: {}}, ckpt)
            wrapped["a"]({})
            wrapped["b"]({})
            wrapped["a"]({})
            files = sorted(f for f in os.listdir(tmp) if f.startswith("ckpt_"))
            steps = [int(f.split("_")[1]) for f in files]
            assert steps == [0, 1, 2]


# ===========================================================================
# 6. executor: critique clearing + vacuous UNSAT
# ===========================================================================

class _FakeCEGIS:
    def __init__(self, result):
        self._result = result

    def run_with_repair(self, z3_code, max_repairs=None, **kwargs):
        return self._result


class TestExecutorCritiqueAndVacuity:
    def test_sat_clears_stale_critique(self):
        from domain.graph_nodes import executor_node
        state = {
            "z3_code": "from z3 import *",
            "iterations": 0, "executor_runs": 0,
            "findings": [{"id": 1}],
            "supervisor_critique": "Z3 Syntax/Execution Error: old",
        }
        updates = executor_node(state, _FakeCEGIS({"status": "sat", "output": "BUG FOUND"}))
        assert updates["supervisor_critique"] is None

    def test_genuine_unsat_pops_and_clears_critique(self, monkeypatch):
        import domain.graph_nodes as gn
        from domain.graph_nodes import executor_node
        # No harness -> probe returns None -> UNSAT is trustworthy.
        monkeypatch.setattr(gn, "_probe_harness_vacuity", lambda state: None)
        state = {
            "z3_code": "from z3 import *",
            "iterations": 0, "executor_runs": 0,
            "findings": [{"id": 1}, {"id": 2}],
            "supervisor_critique": "stale",
        }
        updates = executor_node(state, _FakeCEGIS({"status": "unsat", "output": "holds"}))
        assert updates["findings"] == [{"id": 2}]
        assert updates["supervisor_critique"] is None
        assert updates["executor_runs"] == 0  # fresh budget for next finding

    def test_vacuous_unsat_keeps_finding_and_sets_critique(self, monkeypatch):
        import domain.graph_nodes as gn
        from domain.graph_nodes import executor_node
        monkeypatch.setattr(gn, "_probe_harness_vacuity",
                            lambda state: "harness model is unsatisfiable")
        state = {
            "z3_code": "from z3 import *",
            "iterations": 0, "executor_runs": 0,
            "findings": [{"id": 1, "intent": "x"}],
        }
        updates = executor_node(state, _FakeCEGIS({"status": "unsat", "output": "holds"}))
        # Finding must NOT be consumed.
        assert "findings" not in updates
        assert updates["vacuity_status"] == "vacuous"
        assert updates["supervisor_critique"].startswith("Z3 VACUOUS MODEL")


class TestProbeHarnessVacuity:
    def test_no_harness_returns_none(self):
        from domain.graph_nodes import _probe_harness_vacuity
        assert _probe_harness_vacuity({"findings": [{"id": 1}]}) is None

    def test_unsat_probe_flags_vacuous(self, monkeypatch):
        import domain.graph_nodes as gn
        monkeypatch.setattr(gn, "compose_reachability_script", lambda h: "script")
        monkeypatch.setattr(gn, "run_z3", lambda s: {"status": "unsat"})
        state = {"findings": [{"id": 1}], "semantic_harness": {"code": "x"}}
        reason = gn._probe_harness_vacuity(state)
        assert reason and "unsatisfiable" in reason

    def test_sat_probe_trusts_unsat(self, monkeypatch):
        import domain.graph_nodes as gn
        monkeypatch.setattr(gn, "compose_reachability_script", lambda h: "script")
        monkeypatch.setattr(gn, "run_z3", lambda s: {"status": "sat"})
        state = {"findings": [{"id": 1}], "semantic_harness": {"code": "x"}}
        assert gn._probe_harness_vacuity(state) is None


# ===========================================================================
# 7. compositor malformed-payload guards
# ===========================================================================

class _FakeCompInspector:
    def __init__(self, raw):
        self.compositor_agent = object()
        self.compositor_prompt = "sys"
        self._raw = raw

    def _invoke(self, agent, sysp, user):
        return self._raw

    def extract_json(self, raw):
        from domain.json_extract import extract_json_value
        value, err = extract_json_value(raw)
        if isinstance(value, list):
            return {"findings": value}
        if isinstance(value, dict):
            return value
        return {"findings": []}


class TestCompositorGuards:
    def _results(self):
        return [{"finding": {"intent": "a bug", "target_function": "deposit"}}]

    def test_scalar_json_returns_empty(self):
        from domain.pipeline import _run_compositor_phase
        ins = _FakeCompInspector('"just a string"')
        out = _run_compositor_phase("C", self._results(), "contract C{}", "", ins)
        assert out == []

    def test_findings_not_a_list_returns_empty(self):
        from domain.pipeline import _run_compositor_phase
        ins = _FakeCompInspector('{"findings": {"a": 1}}')
        out = _run_compositor_phase("C", self._results(), "contract C{}", "", ins)
        assert out == []

    def test_non_dict_entries_filtered(self, ):
        from domain.pipeline import _run_compositor_phase
        ins = _FakeCompInspector('{"findings": [42, "junk", {"intent": "chain", "target_function": "a->b"}]}')
        out = _run_compositor_phase("C", self._results(), "contract C{}", "", ins, app=None)
        assert len(out) == 1

    def test_non_dict_results_ignored(self):
        from domain.pipeline import _run_compositor_phase
        ins = _FakeCompInspector('{"findings": []}')
        out = _run_compositor_phase("C", ["not-a-dict", 5], "contract C{}", "", ins)
        assert out == []


# ===========================================================================
# 8. extractor negative counterexample values
# ===========================================================================

class TestExtractorNegativeValues:
    def test_negative_value_parsed_as_int(self):
        from domain.extractor import OutputExtractor
        out = OutputExtractor.parse_z3_counterexample("BUG FOUND: delta = -5")
        assert out.get("delta") == -5

    def test_positive_value_still_int(self):
        from domain.extractor import OutputExtractor
        out = OutputExtractor.parse_z3_counterexample("BUG FOUND: amount = 42")
        assert out.get("amount") == 42

    def test_arrow_form_negative(self):
        from domain.extractor import OutputExtractor
        out = OutputExtractor.parse_z3_counterexample("balance -> -100")
        assert out.get("balance") == -100


# ===========================================================================
# 9. content_to_text
# ===========================================================================

class TestContentToText:
    def test_str_passthrough(self):
        from domain.llm_utils import content_to_text
        assert content_to_text("hello") == "hello"

    def test_none_empty(self):
        from domain.llm_utils import content_to_text
        assert content_to_text(None) == ""

    def test_block_dicts(self):
        from domain.llm_utils import content_to_text
        blocks = [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]
        assert content_to_text(blocks) == "ab"

    def test_list_of_strings(self):
        from domain.llm_utils import content_to_text
        assert content_to_text(["x", "y"]) == "xy"


# ===========================================================================
# 10. gatekeeper out-of-scope clears critique
# ===========================================================================

class _OOSScopeGatekeeper:
    def is_finding_in_scope(self, finding, state):
        return False


class TestGatekeeperOutOfScope:
    def test_out_of_scope_consumes_and_clears_critique(self):
        from domain.graph_nodes import gatekeeper_node
        state = {
            "findings": [{"id": 1}, {"id": 2}],
            "supervisor_critique": "stale critique",
        }
        updates = gatekeeper_node(state, _OOSScopeGatekeeper())
        assert updates["findings"] == [{"id": 2}]
        assert updates["supervisor_critique"] is None
        assert updates["executor_runs"] == 0
