"""Offline tests for the hunter's empty-response handling and the
route_after_hunter short-circuit that prevents API-credit burn on
quota/rate-limit exhaustion.

Root cause being tested: when the LLM provider returns HTTP-200 with
empty content or only <think>...</think> reasoning (no JSON payload),
the previous behavior was:
  1. _parse_hunter_output returned (findings=[], err="char 0")
  2. hunter treated it as a generic parse failure
  3. route_after_hunter retried (outer loop) up to HUNTER_MAX_PARSE_RETRIES
  4. each retry burned API credits on a call that was guaranteed to fail

The fix:
  1. _parse_hunter_output returns a 3-tuple (findings, err, provider_empty)
  2. hunter tracks empty_passes; if ALL passes empty, sets hunter_provider_empty
  3. route_after_hunter short-circuits to END when hunter_provider_empty is True
"""
import pytest


# ---------------------------------------------------------------------------
# Fake inspector for _parse_hunter_output tests
# ---------------------------------------------------------------------------

class _FakeInspector:
    """Mimics Inspector.extract_json: always returns empty findings."""
    def extract_json(self, raw):
        return {"findings": []}


# ===========================================================================
# 1. _parse_hunter_output 3-tuple contract
# ===========================================================================

class TestParseHunterOutputProviderEmpty:
    def test_empty_input_flags_provider_empty(self):
        from domain.graph_nodes import _parse_hunter_output
        findings, err, empty = _parse_hunter_output("", _FakeInspector())
        assert findings == []
        assert err is not None
        assert empty is True

    def test_think_only_flags_provider_empty(self):
        from domain.graph_nodes import _parse_hunter_output
        raw = "<think>some reasoning</think>"
        findings, err, empty = _parse_hunter_output(raw, _FakeInspector())
        assert findings == []
        assert err is not None
        assert empty is True

    def test_nested_think_flags_provider_empty(self):
        from domain.graph_nodes import _parse_hunter_output
        raw = "<think>a</think>b<think>c</think>"
        findings, err, empty = _parse_hunter_output(raw, _FakeInspector())
        assert findings == []
        # After stripping both <think> blocks, "b" remains -> NOT provider-empty
        # (it's garbage JSON). Verify the distinction is made correctly.
        assert empty is False

    def test_empty_markdown_fence_flags_provider_empty(self):
        from domain.graph_nodes import _parse_hunter_output
        raw = "```json\n```"
        findings, err, empty = _parse_hunter_output(raw, _FakeInspector())
        assert findings == []
        assert err is not None
        assert empty is True

    def test_garbage_json_not_provider_empty(self):
        from domain.graph_nodes import _parse_hunter_output
        raw = "{not valid json"
        findings, err, empty = _parse_hunter_output(raw, _FakeInspector())
        assert findings == []
        assert err is not None
        assert empty is False

    def test_valid_json_not_provider_empty(self):
        from domain.graph_nodes import _parse_hunter_output
        raw = '{"findings": [{"severity": "high", "intent": "bug"}]}'
        findings, err, empty = _parse_hunter_output(raw, _FakeInspector())
        assert len(findings) == 1
        assert err is None
        assert empty is False

    def test_valid_json_with_think_prefix(self):
        from domain.graph_nodes import _parse_hunter_output
        raw = '<think>reasoning</think>\n```json\n{"findings": [{"x": 1}]}\n```'
        findings, err, empty = _parse_hunter_output(raw, _FakeInspector())
        assert len(findings) == 1
        assert err is None
        assert empty is False


# ===========================================================================
# 2. route_after_hunter short-circuit
# ===========================================================================

class TestRouteAfterHunterShortCircuit:
    def test_provider_empty_skips_retry_goes_to_end(self):
        """The critical behavior: provider_empty=True must bypass the retry
        path entirely, even when hunter_parse_error is set and retries remain."""
        from domain.pipeline import route_after_hunter
        state = {
            "hunter_provider_empty": True,
            "hunter_parse_error": "LLM response was empty",
            "findings": [],
            "hunter_retries": 0,
            "current_focus_function": "flashLoan",
        }
        assert route_after_hunter(state) == "__end__"

    def test_parse_error_without_provider_empty_retries(self):
        """Garbage JSON (provider_empty=False) should still retry — the cause
        might be a one-off hallucination, and a retry could succeed."""
        from domain.pipeline import route_after_hunter
        state = {
            "hunter_provider_empty": False,
            "hunter_parse_error": "garbage JSON",
            "findings": [],
            "hunter_retries": 0,
            "current_focus_function": "flashLoan",
        }
        assert route_after_hunter(state) == "bug_hunter"

    def test_parse_error_retries_exhausted_goes_to_end(self):
        from domain.pipeline import route_after_hunter
        state = {
            "hunter_provider_empty": False,
            "hunter_parse_error": "garbage JSON",
            "findings": [],
            "hunter_retries": 99,  # above HUNTER_MAX_PARSE_RETRIES
            "current_focus_function": "flashLoan",
        }
        assert route_after_hunter(state) == "__end__"

    def test_no_findings_no_error_goes_to_end(self):
        from domain.pipeline import route_after_hunter
        state = {
            "hunter_parse_error": None,
            "findings": [],
            "current_focus_function": "flashLoan",
        }
        assert route_after_hunter(state) == "__end__"

    def test_findings_present_routes_to_supervisor(self):
        from domain.pipeline import route_after_hunter
        state = {
            "hunter_parse_error": None,
            "findings": [{"severity": "high"}],
            "current_focus_function": "flashLoan",
        }
        assert route_after_hunter(state) == "supervisor"

    def test_provider_empty_missing_key_treated_as_false(self):
        """Legacy callers that don't set hunter_provider_empty must behave
        as if it were False (normal retry logic)."""
        from domain.pipeline import route_after_hunter
        state = {
            "hunter_parse_error": "garbage JSON",
            "findings": [],
            "hunter_retries": 0,
            "current_focus_function": "flashLoan",
        }
        # No hunter_provider_empty key -> retry, not short-circuit
        assert route_after_hunter(state) == "bug_hunter"
