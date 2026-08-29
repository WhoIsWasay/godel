"""Phase 4 tests: routing functions, verdict classification, Z3 sentinel
matrix, and Gatekeeper forge-output classification (mocked subprocess).
Run: python -X utf8 testOfCode/test_phase4.py"""
import os
import subprocess
import sys
import tempfile
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    print(("  [PASS] " if cond else "  [FAIL] ") + name)
    PASS, FAIL = PASS + (1 if cond else 0), FAIL + (0 if cond else 1)


# ============================================================ routing
print("== T1: graph routing functions ==")
from domain.pipeline import (route_after_hunter, route_after_supervisor,   # noqa: E402
                             route_after_specifier, route_after_executor,
                             route_after_gatekeeper, route_after_fixer,
                             _classify_terminal_state)
from domain.graph_nodes import supervisor_node  # noqa: E402  (import sanity)

END = "__end__"

r = route_after_hunter({"findings": [{"id": 1}], "hunter_parse_error": None})
check("findings -> supervisor", r == "supervisor")
r = route_after_hunter({"findings": [], "hunter_parse_error": None})
check("clean no-findings -> END", r == END)
r = route_after_hunter({"findings": [], "hunter_parse_error": "bad json",
                        "hunter_retries": 0})
check("parse failure retries -> bug_hunter", r == "bug_hunter")
r = route_after_hunter({"findings": [], "hunter_parse_error": "bad json",
                        "hunter_retries": 99})
check("retries exhausted -> END (not silent-safe)", r == END)

r = route_after_supervisor({"supervisor_runs": 3, "supervisor_critique": "x"})
check("supervisor limit -> END", r == END)
r = route_after_supervisor({"supervisor_runs": 1, "supervisor_critique": "fix it"})
check("critique -> hunter loop", r == "bug_hunter")
r = route_after_supervisor({"supervisor_runs": 1, "supervisor_critique": None})
check("approved -> specifier", r == "specifier")

r = route_after_specifier({"supervisor_critique": "c", "z3_result": {"status": "error"}})
check("leftover critique + z3 error stays executor-path", r == "executor")
r = route_after_specifier({"supervisor_critique": "c", "z3_result": {"status": "sat"}})
check("stale critique after sat -> supervisor detour", r == "supervisor")
r = route_after_specifier({"supervisor_critique": None, "z3_result": None})
check("normal specifier -> executor", r == "executor")

r = route_after_executor({"z3_result": {"status": "sat"}, "executor_runs": 0})
check("SAT -> gatekeeper", r == "gatekeeper")
r = route_after_executor({"z3_result": {"status": "unsat"}, "executor_runs": 0})
check("UNSAT -> END (proven)", r == END)
r = route_after_executor({"z3_result": {"status": "error"}, "executor_runs": 1})
check("error under limit -> specifier refine", r == "specifier")
r = route_after_executor({"z3_result": {"status": "inconclusive"}, "executor_runs": 4})
check("error at limit -> END inconclusive", r == END)

r = route_after_gatekeeper({"verified_bugs": [{"f": 1}], "findings": []})
check("confirmed -> fixer", r == "fixer")
r = route_after_gatekeeper({"verified_bugs": [], "findings": [{"id": 2}]})
check("dropped finding w/ queue -> specifier", r == "specifier")
r = route_after_gatekeeper({"verified_bugs": [], "findings": []})
check("nothing left -> END", r == END)

r = route_after_fixer({"findings": [{"id": 3}]})
check("fixer w/ queued findings -> specifier", r == "specifier")
r = route_after_fixer({"findings": []})
check("fixer done -> END", r == END)

# ============================================================ classification
print("== T2: terminal-state classification matrix ==")


def cls(state):
    return _classify_terminal_state({
        "verified_bugs": [], "findings": [], "supervisor_runs": 0,
        "supervisor_critique": None, "executor_runs": 0, **state})


check("hunter parse failure labeled analysis_failed",
      cls({"hunter_parse_error": "x"}).startswith("analysis_failed"))
check("queued abort labeled aborted",
      cls({"findings": [{"id": 1}]}).startswith("aborted"))
v = cls({"executor_runs": 4, "z3_result": {"status": "error"}})
check("exhausted executor NOT proven safe", "NOT proven safe" in v)
v = cls({"z3_result": {"status": "unsat"}, "model_quality": None})
check("legacy UNSAT label kept", "mathematically safe" in v)

# ============================================================ z3 sentinels
print("== T3: Z3 sentinel matrix ==")
from domain.z3_runner import run_z3  # noqa: E402

r = run_z3("print('BUG FOUND:', 1)")
check("sat sentinel alone -> sat", r["status"] == "sat")
r = run_z3("print('Property holds')")
check("unsat sentinel alone -> unsat", r["status"] == "unsat")
r = run_z3("print('BUG FOUND:')\nprint('Property holds')")
check("both sentinels -> inconclusive (never guess)", r["status"] == "inconclusive")
r = run_z3("print('nothing relevant')")
check("no sentinel -> inconclusive", r["status"] == "inconclusive")
r = run_z3("raise SystemExit(2)")
check("nonzero exit -> error", r["status"] == "error")
r = run_z3("raise ValueError('boom')")
check("exception -> error", r["status"] == "error")

print("== T3b: Z3 script safety gate ==")
from domain.z3_runner import validate_script  # noqa: E402

check("benign property script passes gate",
      validate_script("from z3 import *\nsolver, V = build_model()\n"
                      "if solver.check() == sat:\n    print('BUG FOUND:', solver.model())\n"
                      "else:\n    print('Property holds')") is None)
check("os import rejected", "forbidden import" in (validate_script("import os") or ""))
check("subprocess via from-import rejected",
      "forbidden import" in (validate_script("from subprocess import run") or ""))
check("eval call rejected", "forbidden call" in (validate_script("eval('1+1')") or ""))
check("open() rejected", "forbidden call" in (validate_script("open('.env')") or ""))
check("__import__ rejected", "forbidden call" in (validate_script("__import__('os')") or ""))
check("dunder class escape rejected",
      validate_script("x = ''.__class__") is not None)
check("dunder globals reference rejected",
      validate_script("g = __globals__") is not None)

r = run_z3("import os\nprint('BUG FOUND:')")
check("gate rejects hostile script BEFORE execution (never sat)",
      r["status"] == "error" and "Safety gate" in (r.get("error") or ""))

from domain import config as cfg  # noqa: E402
saved = cfg.Z3_TIMEOUT_SECONDS
try:
    cfg.Z3_TIMEOUT_SECONDS = 1.0
    r = run_z3("import time; time.sleep(10)")
    check("timeout -> error", r["status"] == "error" and "timeout" in (r.get("error") or "").lower())
finally:
    cfg.Z3_TIMEOUT_SECONDS = saved

# ============================================================ gatekeeper
print("== T4: Gatekeeper forge-classification matrix (mocked) ==")
from domain.gatekeeper import FoundryGatekeeper  # noqa: E402

tmpdir = tempfile.mkdtemp(prefix="gk_test_")
gk = FoundryGatekeeper(project_root=tmpdir, verifier_agent=None)


def fake_run(returncode=0, stdout="", stderr=""):
    p = MagicMock()
    p.returncode = returncode
    p.stdout = stdout
    p.stderr = stderr
    return p


COMPILE_ERR = "Error: ParserError: Source ... \nCompiler run failed"

with patch.object(subprocess, "run", return_value=fake_run(0, "Ran 1 tests: PASS", "")):
    st, _ = gk.execute_qc_validation("// ok", max_retries=1)
    check("passing suite -> property_held (false positive dropped)", st == "property_held")

with patch.object(subprocess, "run", return_value=fake_run(1, "Ran 1 tests: FAIL. 1 passed? no", "")):
    st, _ = gk.execute_qc_validation("// bug", max_retries=1)
    check("failing suite -> confirmed (bug proven)", st == "confirmed")

with patch.object(subprocess, "run", return_value=fake_run(1, COMPILE_ERR, "")):
    st, out = gk.execute_qc_validation("// broken", max_retries=1)
    check("compile failure (no healer) -> compile_failed", st == "compile_failed")

with patch.object(subprocess, "run", return_value=fake_run(1, "Ran 2 tests: FAIL", "")) as m:
    st, _ = gk.execute_qc_validation("// runtime revert has 'Error (' text", max_retries=1)
    check("runtime revert != compile failure (no false heal trigger)", st == "confirmed")

with patch.object(subprocess, "run", return_value=fake_run(137, "", "")):
    st, _ = gk.execute_qc_validation("// crash", max_retries=1)
    check("abnormal exit w/o FAIL -> inconclusive (kept for review)", st == "inconclusive")

with patch.object(subprocess, "run", return_value=fake_run(0, "No tests found in file", "")):
    st, _ = gk.execute_qc_validation("// empty harness", max_retries=1)
    check("zero matched tests -> harness_error", st == "harness_error")

with patch.object(subprocess, "run", side_effect=FileNotFoundError("forge")):
    st, _ = gk.execute_qc_validation("// x", max_retries=1)
    check("missing forge -> tool_missing", st == "tool_missing")

with patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired(cmd="forge", timeout=45)):
    st, _ = gk.execute_qc_validation("// slow", max_retries=1)
    check("forge timeout -> timeout status", st == "timeout")

# CEGIS heal path: compile fails once then passes
seq = [fake_run(1, COMPILE_ERR, ""), fake_run(0, "Ran 1 tests: PASS", "")]
healer = MagicMock()
healer.heal_test_suite.return_value = "// healed"
gk_heal = FoundryGatekeeper(project_root=tmpdir, verifier_agent=healer)
with patch.object(subprocess, "run", side_effect=seq):
    st, _ = gk_heal.execute_qc_validation("// broken", max_retries=2)
    check("CEGIS heal retried then classified", st == "property_held")
    check("healer invoked exactly once", healer.heal_test_suite.call_count == 1)

# scope filter
in_scope = FoundryGatekeeper.is_finding_in_scope(
    {"title": "arithmetic precision loss"}, {"bug_report": None})
out_scope = FoundryGatekeeper.is_finding_in_scope(
    {"title": "single-step ownership transfer centralization risk"}, {"bug_report": None})
check("scope filter keeps math bugs", in_scope is True)
check("scope filter drops governance/centralization", out_scope is False)

print("== T5: forge --json structured verdicts ==")
from domain.gatekeeper import classify_forge_json  # noqa: E402

check("non-JSON stdout -> None (legacy fallback)", classify_forge_json("Ran 1 tests: PASS") is None)
check("malformed JSON -> None", classify_forge_json("{oops") is None)

JSON_ALL_PASS = '{"VaultTest":{"test_x":{"success": true}},"OtherTest":{"test_y":{"success": true}}}'
v = classify_forge_json(JSON_ALL_PASS)
check("JSON all-success -> property_held", v == ("property_held", 2))

JSON_ONE_FAIL = '{"T":{"test_a":{"success": true},"test_b":{"success": false}}}'
v = classify_forge_json(JSON_ONE_FAIL)
check("JSON any failure -> confirmed", v == ("confirmed", 2))

check("JSON empty object -> harness_error", classify_forge_json("{}") == ("harness_error", 0))
check("JSON no success fields -> harness_error",
      classify_forge_json('{"meta": {"version": "1.0"}}') == ("harness_error", 0))

with patch.object(subprocess, "run", return_value=fake_run(1, JSON_ONE_FAIL, "")):
    st, _ = gk.execute_qc_validation("// json bug", max_retries=1)
    check("end-to-end JSON failure -> confirmed via structured path", st == "confirmed")

with patch.object(subprocess, "run", return_value=fake_run(0, JSON_ALL_PASS, "")):
    st, _ = gk.execute_qc_validation("// json pass", max_retries=1)
    check("end-to-end JSON clean -> property_held via structured path", st == "property_held")

with patch.object(subprocess, "run", return_value=fake_run(0, "{}", "")):
    st, _ = gk.execute_qc_validation("// json empty", max_retries=1)
    check("end-to-end JSON zero results -> harness_error", st == "harness_error")

with patch.object(subprocess, "run", return_value=fake_run(1, "", COMPILE_ERR)):
    st, _ = gk.execute_qc_validation("// json-mode compile error", max_retries=1)
    check("JSON-mode compile failure still -> compile_failed", st == "compile_failed")

# ============================================================ isolator routing
print("== T6: Isolator model routing ==")
import domain.pipeline as pl  # noqa: E402
from domain import config as _cfg  # noqa: E402

_default_model = getattr(pl.llm_isolator, "model_name",
                         getattr(pl.llm_isolator, "model", ""))
if _cfg.ISOLATOR_MODEL:
    check("flag set -> isolator uses configured model", _default_model == _cfg.ISOLATOR_MODEL)
else:
    check("unset flag -> isolator falls back to reasoning client",
          pl.llm_isolator is pl.llm_pro)
# Pro was retired (commit aa06bca): the reasoning client runs flash with a
# max-reasoning budget, and downstream machine verification (supervisor/Z3/
# Foundry) carries the soundness, not model tier.
check("reasoning client runs flash (Pro retired)",
      getattr(pl.llm_pro, "model_name", getattr(pl.llm_pro, "model", "")) == "deepseek-v4-flash")
check("flag propagates to Inspector.isolator_agent",
      pl.inspector.isolator_agent is pl.llm_isolator)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
