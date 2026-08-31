"""Offline ironclad tests — zero API calls.

Covers the three hardening pillars:
  1. Silent-drop elimination (transient markers, error/incomplete artifacts)
  2. Vacuity defense (SANITY sentinel, vacuous routing)
  3. Property quality gates (strict lint)

Uses real z3 subprocess execution where noted (z3 installed locally).
Run:  python -c "..." harness in CI, or pytest tests/test_ironclad.py
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ------------------------------------------------ 1. transient error markers

def test_transient_markers_network():
    from domain.pipeline import _is_transient_error
    assert _is_transient_error(ConnectionError("connection reset by peer"))
    assert _is_transient_error(Exception("getaddrinfo failed for api.deepseek.com"))
    assert _is_transient_error(Exception("Read timed out after 120s"))


def test_transient_markers_rate_limits():
    """Rate-limit exhaustion must retry, not silently kill the function
    (PoolTogether M-01 class)."""
    from domain.pipeline import _is_transient_error
    assert _is_transient_error(Exception("Error code: 429 - rate limit exceeded"))
    assert _is_transient_error(Exception("Too Many Requests"))
    assert _is_transient_error(Exception("quota exceeded for this account"))
    assert _is_transient_error(Exception("server overloaded, try again later"))
    assert _is_transient_error(Exception("Error code: 503 - service unavailable"))
    assert _is_transient_error(Exception("502 Bad Gateway"))


def test_transient_markers_logic_errors_not_retried():
    from domain.pipeline import _is_transient_error
    assert not _is_transient_error(ValueError("invalid finding schema"))
    assert not _is_transient_error(KeyError("target_function"))
    assert not _is_transient_error(Exception("JSON decode failed"))


# ------------------------------------------------- 2. sentinel classification

def test_classify_sentinels_vacuous_priority():
    """A failed SANITY probe poisons the run even if a BUG FOUND sentinel
    also appears later — the model was impossible."""
    from domain.z3_runner import _classify_sentinels
    status, err = _classify_sentinels("SANITY: unsat\nProperty holds")
    assert status == "vacuous"
    assert "over-constrained" in err

    status, _ = _classify_sentinels("SANITY: unsat\nBUG FOUND: x=1")
    assert status == "vacuous"


def test_classify_sentinels_normal_matrix():
    from domain.z3_runner import _classify_sentinels
    assert _classify_sentinels("SANITY: sat\nBUG FOUND: amount=1")[0] == "sat"
    assert _classify_sentinels("SANITY: sat\nScenario 1: Property holds")[0] == "unsat"
    # Both sentinels -> ambiguous
    assert _classify_sentinels("BUG FOUND: x\nProperty holds")[0] == "inconclusive"
    # Neither -> inconclusive (never guess)
    assert _classify_sentinels("some random output")[0] == "inconclusive"


# --------------------------------------------------- 3. property quality lint

GOOD_SCRIPT = """from z3 import *
s = Solver()
x = BitVec('x', 256)
s.add(UGT(x, 0), ULT(x, 100))
s.push()
print("SANITY:", s.check())
s.pop()
s.add(x == 1)
if s.check() == sat:
    print("BUG FOUND:", s.model())
else:
    print("Property holds")
"""


def test_lint_accepts_good_script():
    from domain.z3_runner import _lint_property_quality
    assert _lint_property_quality(GOOD_SCRIPT) is None


def test_lint_rejects_no_constraints():
    from domain.z3_runner import _lint_property_quality
    script = "from z3 import *\ns = Solver()\nprint('SANITY:', s.check())\ns.check()"
    issue = _lint_property_quality(script)
    assert issue and "no solver.add" in issue


def test_lint_rejects_no_check():
    from domain.z3_runner import _lint_property_quality
    script = "from z3 import *\ns = Solver()\nprint('SANITY: sat')\ns.add(1 == 1)"
    issue = _lint_property_quality(script)
    assert issue and "check()" in issue


def test_lint_rejects_missing_sanity_probe():
    from domain.z3_runner import _lint_property_quality
    script = "from z3 import *\ns = Solver()\ns.add(1 == 1)\ns.check()"
    issue = _lint_property_quality(script)
    assert issue and "SANITY" in issue


# ------------------------------------- 4. real z3 execution (offline, local)

def test_run_z3_detects_vacuous_model_end_to_end():
    """An over-constrained base model must be flagged vacuous, never 'unsat'."""
    from domain.z3_runner import run_z3
    script = """from z3 import *
s = Solver()
x = BitVec('x', 256)
s.add(UGT(x, 100))
s.add(ULT(x, 10))  # contradicts the bound above -> base model unreachable
s.push()
print("SANITY:", s.check())
s.pop()
s.add(x == 50)
if s.check() == sat:
    print("BUG FOUND:", s.model())
else:
    print("Property holds")
"""
    result = run_z3(script)
    assert result["status"] == "vacuous", f"expected vacuous, got {result}"
    assert "over-constrained" in result["error"]


def test_run_z3_sat_end_to_end():
    from domain.z3_runner import run_z3
    script = """from z3 import *
s = Solver()
x = BitVec('x', 256)
s.add(UGE(x, 0), ULT(x, 100))
s.push()
print("SANITY:", s.check())
s.pop()
s.add(x == 42)
if s.check() == sat:
    print("BUG FOUND:", s.model())
else:
    print("Property holds")
"""
    result = run_z3(script)
    assert result["status"] == "sat", f"expected sat, got {result}"


def test_run_z3_unsat_end_to_end():
    from domain.z3_runner import run_z3
    script = """from z3 import *
s = Solver()
x = BitVec('x', 256)
s.add(UGE(x, 0), ULT(x, 100))
s.push()
print("SANITY:", s.check())
s.pop()
s.add(UGT(x, 1000))  # impossible under bounds -> genuine unsat
if s.check() == sat:
    print("BUG FOUND:", s.model())
else:
    print("Property holds")
"""
    result = run_z3(script)
    assert result["status"] == "unsat", f"expected unsat, got {result}"


def test_run_z3_strict_rejects_missing_sanity_before_execution():
    """strict=True (the CEGIS path) rejects degenerate scripts pre-execution."""
    from domain.z3_runner import run_z3
    script = "from z3 import *\ns = Solver()\ns.add(1 == 1)\nprint('Property holds')\ns.check()"
    result = run_z3(script, strict=True)
    assert result["status"] == "error"
    assert "SANITY" in result["error"]


def test_run_z3_nonstrict_skips_lint():
    """Harness/vacuity-probe scripts (trusted code) skip the quality lint."""
    from domain.z3_runner import run_z3
    script = "print('Property holds')"
    result = run_z3(script, strict=False)
    assert result["status"] == "unsat"


# ---------------------------------------------- 5. silent-drop artifact shape

def test_error_finding_shape():
    from domain.pipeline import _error_finding
    f = _error_finding("Vault", "deposit", ConnectionError("getaddrinfo failed"))
    assert f["qc_status"] == "graph_error"
    assert f["function"] == "deposit"
    assert "NOT verified" in f["summary"]
    assert "ConnectionError" in f["summary"]


def test_incomplete_finding_shape():
    from domain.pipeline import _incomplete_finding
    f = _incomplete_finding("Vault", "withdraw", "executor exhausted retries")
    assert f["qc_status"] == "analysis_incomplete"
    assert f["function"] == "withdraw"
    assert "NOT a safety verdict" in f["summary"]


# ------------------------------------------- 6. incomplete-flag truth table

def test_should_flag_incomplete_matrix():
    from domain.pipeline import _should_flag_incomplete
    from domain import config

    # Clean safe verdict -> no flag
    assert _should_flag_incomplete({"findings": [], "z3_result": {"status": "unsat"}}) is None
    # Leftover queued findings -> flag
    assert _should_flag_incomplete({"findings": [{"id": 1}]}) is not None
    # Hunter parse failure with nothing queued -> flag
    assert _should_flag_incomplete({"hunter_parse_error": "bad json", "findings": []}) is not None
    # Executor exhausted on errors -> flag
    assert _should_flag_incomplete({
        "findings": [], "executor_runs": config.EXECUTOR_MAX_ITERATIONS,
        "z3_result": {"status": "error"},
    }) is not None
    # Executor exhausted on vacuous -> flag
    assert _should_flag_incomplete({
        "findings": [], "executor_runs": config.EXECUTOR_MAX_ITERATIONS,
        "z3_result": {"status": "vacuous"},
    }) is not None
    # Harness vacuity detected -> flag
    assert _should_flag_incomplete({"findings": [], "vacuity_status": "vacuous"}) is not None
    # SANITY vacuous verdict -> flag
    assert _should_flag_incomplete({"findings": [], "z3_result": {"status": "vacuous"}}) is not None


# --------------------------------------------- 7. executor vacuous handling

class _FakeCEGIS:
    def __init__(self, result):
        self._result = result

    def run_with_repair(self, z3_code, max_repairs=None, **kwargs):
        return self._result


def test_executor_vacuous_keeps_finding_and_sets_critique():
    from domain.graph_nodes import executor_node
    state = {
        "z3_code": "from z3 import *",
        "iterations": 0,
        "executor_runs": 0,
        "findings": [{"id": 1, "intent": "zero shares"}],
    }
    fake = _FakeCEGIS({"status": "vacuous", "error": "SANITY probe unsat"})
    updates = executor_node(state, fake)
    # Finding must NOT be popped — it needs another specifier attempt
    assert updates.get("findings") is None or updates["findings"] == [{"id": 1, "intent": "zero shares"}]
    assert "VACUOUS" in updates["supervisor_critique"]
    assert updates["z3_result"]["status"] == "vacuous"


def test_executor_unsat_pops_finding():
    from domain.graph_nodes import executor_node
    state = {
        "z3_code": "from z3 import *",
        "iterations": 0,
        "executor_runs": 0,
        "findings": [{"id": 1}, {"id": 2}],
        "semantic_harness": None,
    }
    fake = _FakeCEGIS({"status": "unsat", "output": "Property holds"})
    updates = executor_node(state, fake)
    assert updates["findings"] == [{"id": 2}]


# ----------------------------------------------------- 8. routing decisions

def test_route_after_executor_matrix():
    from domain.pipeline import route_after_executor
    from langgraph.graph import END
    from domain import config

    # vacuous below retry limit -> back to specifier
    assert route_after_executor({"z3_result": {"status": "vacuous"}, "executor_runs": 0}) == "specifier"
    # vacuous at retry limit -> END (and the incomplete artifact surfaces it)
    assert route_after_executor({
        "z3_result": {"status": "vacuous"},
        "executor_runs": config.EXECUTOR_MAX_ITERATIONS,
    }) == END
    # sat -> gatekeeper
    assert route_after_executor({"z3_result": {"status": "sat"}}) == "gatekeeper"
    # unsat with more findings -> specifier for the next finding
    assert route_after_executor({"z3_result": {"status": "unsat"}, "findings": [{"id": 2}]}) == "specifier"
    # unsat with no findings -> END
    assert route_after_executor({"z3_result": {"status": "unsat"}, "findings": []}) == END


def test_route_after_specifier_keeps_vacuous_feedback_off_supervisor():
    from domain.pipeline import route_after_specifier
    # vacuous repair feedback must go straight to executor (via specifier path),
    # never detouring through the supervisor and burning its iteration budget
    assert route_after_specifier({
        "supervisor_critique": "Z3 VACUOUS MODEL: ...",
        "z3_result": {"status": "vacuous"},
    }) == "executor"
    # A genuine supervisor rejection (unsat last run) still detours to supervisor
    assert route_after_specifier({
        "supervisor_critique": "Variable not found",
        "z3_result": {"status": "unsat"},
    }) == "supervisor"


# --------------------------------------- 9. repair feedback reaches specifier

def test_build_prompt_injects_repair_feedback():
    from domain.propertygenerator import PropertyGenerator
    from unittest.mock import patch

    gen = PropertyGenerator(agent=None)
    gen.build_prompt(
        {"intent": "shares > 0", "queries": []},
        "contract Vault {}",
        [],
        repair_feedback="Z3 VACUOUS MODEL: preconditions contradict",
    )
    assert "<repair_feedback>" in gen.prompt
    assert "Z3 VACUOUS MODEL" in gen.prompt

    gen.build_prompt({"intent": "shares > 0", "queries": []}, "contract Vault {}", [])
    assert "<repair_feedback>" not in gen.prompt


# ---------------------------------------- 10. specifier prompt standards

def test_specifier_prompt_documents_sanity_and_calibration():
    from domain.config import PROMPTS_DIR
    text = (PROMPTS_DIR / "property_generator_prompt.txt").read_text(encoding="utf-8")
    assert "MANDATORY SANITY PROBE" in text
    assert "property_calibration" in text
    assert "LOOSE" in text and "NICHE" in text and "CALIBRATED" in text
    assert 'print("SANITY:", s.check())' in text
