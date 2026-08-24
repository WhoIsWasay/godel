"""
Regression tests for the audit-report fixes (C1-C4, H5, H6 + edge cases).
No network / API keys required. Run:  python testOfCode/test_audit_fixes.py
"""
import sys
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
os.chdir(PROJECT_ROOT)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    if cond:
        PASS.append(name)
        print(f"  [PASS] {name}")
    else:
        FAIL.append(name)
        print(f"  [FAIL] {name} {detail}")


print("== C1: isolated_xml_packet survives LangGraph state ==")
from domain.state import GraphState
check("C1a key declared in GraphState", "isolated_xml_packet" in GraphState.__annotations__)
check("C1b hunter_parse_error declared", "hunter_parse_error" in GraphState.__annotations__)

from langgraph.graph import StateGraph, END

def probe_node(state):
    return {"seen_packet": bool(state.get("isolated_xml_packet"))}

class ProbeState(GraphState):
    seen_packet: bool

g = StateGraph(ProbeState)
g.add_node("probe", probe_node)
g.set_entry_point("probe")
g.add_edge("probe", END)
app = g.compile()
final = app.invoke({"user_contract": "c", "contract_name": "n", "readme_specs": "",
                    "messages": [], "next_agent": "", "mode": "", "intent": "",
                    "queries": [], "findings": [], "verified_bugs": [],
                    "z3_code": "", "iterations": 0, "supervisor_runs": 0,
                    "executor_runs": 0, "poc_test_code": "", "forge_output": "",
                    "qc_status": "", "isolated_xml_packet": "<analysis_packet>X</analysis_packet>"})
check("C1c node receives the packet", final.get("seen_packet") is True)

print("== C2: z3_runner explicit sentinels ==")
from domain.z3_runner import run_z3
r_sat = run_z3("print('BUG FOUND:')\nprint('model')")
check("C2 sat sentinel -> sat", r_sat["status"] == "sat")
r_unsat = run_z3("print('Property holds - no counterexample found')")
check("C2 unsat sentinel -> unsat", r_unsat["status"] == "unsat")
r_silent = run_z3("x = 1")
check("C2 silent exit -> inconclusive (NOT sat)", r_silent["status"] == "inconclusive",
      f"got {r_silent['status']}")
r_both = run_z3("print('BUG FOUND:')\nprint('Property holds')")
check("C2 both sentinels -> inconclusive", r_both["status"] == "inconclusive")
r_err = run_z3("raise RuntimeError('boom')")
check("C2 crash -> error", r_err["status"] == "error")

print("== C3/H6: gatekeeper classification & scope filter ==")
from unittest.mock import patch
import domain.gatekeeper as gk
gate = gk.FoundryGatekeeper(project_root=str(PROJECT_ROOT), verifier_agent=None,
                            debug_dir=str(PROJECT_ROOT / "output" / "debug_tests"))

def fake_run_factory(returncode, stdout, stderr=""):
    def _f(*a, **k):
        import subprocess as sp
        CompletedProcess = type("CP", (), {})
        cp = CompletedProcess()
        cp.returncode = returncode
        cp.stdout = stdout
        cp.stderr = stderr
        return cp
    return _f

with patch.object(gk.subprocess, "run", fake_run_factory(1, "FAIL. Assertion violated.")):
    status, _ = gate.execute_qc_validation("// t", max_retries=1, debug_tag="t_c3_confirmed")
check("C3 rc!=0 + FAIL -> confirmed", status == "confirmed", f"got {status}")

with patch.object(gk.subprocess, "run", fake_run_factory(1, "internal forge panic: OOM")):
    status, _ = gate.execute_qc_validation("// t", max_retries=1, debug_tag="t_c3_inconclusive")
check("C3 rc!=0 without FAIL -> inconclusive (NOT property_held)",
      status == "inconclusive", f"got {status}")

with patch.object(gk.subprocess, "run", fake_run_factory(0, "OK. 1 test passed.")):
    status, _ = guard_status = gate.execute_qc_validation("// t", max_retries=1, debug_tag="t_c3_held")
check("C3 rc==0 clean -> property_held", status == "property_held", f"got {status}")

iso_finding = {"id": 1, "intent": "owner can rug via timelock delay manipulation",
               "constraint": "assert(x > 0)", "target_function": "f",
               "relevant_code": "x = 1;", "tool_hint": "z3",
               "severity_guess": "high", "class": "isolated"}
check("H6 out-of-scope keyword fires on isolator schema (intent)",
      gate.is_finding_in_scope(iso_finding, {"bug_report": ""}) is False)
benign = dict(iso_finding, intent="precision loss lets user drain shares")
check("H6 in-scope finding passes", gate.is_finding_in_scope(benign, {"bug_report": None}) is True,
      "(also covers bug_report=None hardening)")

print("== Edge: supervisor scalar-JSON defense ==")
from domain.graph_nodes import supervisor_node

class FakeMsg:
    def __init__(self, c): self.content = c
class FakeLLM:
    def __init__(self, c): self.c = c
    def invoke(self, m): return FakeMsg(self.c)

base_state = {"findings": [{"id": 1}], "supervisor_runs": 0, "user_contract": "c",
              "current_focus_function": "f"}
upd = supervisor_node(base_state, FakeLLM('"APPROVED"'))
check("supervisor scalar JSON -> forced critique, no crash",
      upd.get("supervisor_critique") is not None)
upd2 = supervisor_node(base_state, FakeLLM('{"status": "APPROVED"}'))
check("supervisor proper APPROVED -> critique cleared",
      upd2.get("supervisor_critique") is None)

print("== Edge: hunter parse failure surfaced ==")
from domain.graph_nodes import bug_hunter_node
class FakeInspectorBroken:
    isolator_agent = "fake-agent"
    isolator_prompt = "fake-prompt"
    def _invoke(self, *a): return "total garbage not json {{{"
    def extract_json(self, r): raise ValueError("no json anywhere")
state_broken = {"isolated_xml_packet": "", "user_contract": "c", "readme_specs": "",
                "supervisor_critique": None, "current_focus_function": "f"}
upd3 = bug_hunter_node(state_broken, FakeInspectorBroken())
check("hunter total parse failure -> hunter_parse_error set",
      upd3.get("hunter_parse_error") is not None and upd3.get("findings") == [])

print("== H5/routing: multi-finding flow ==")
from domain import pipeline as pl
st_bugs_left = {"verified_bugs": [{}], "findings": []}
st_dropped_more = {"verified_bugs": [], "findings": [{}, {}]}
st_done = {"verified_bugs": [], "findings": []}
check("route_after_gatekeeper bugs->fixer", pl.route_after_gatekeeper(st_bugs_left) == "fixer")
check("route_after_gatekeeper drop w/ queue->specifier",
      pl.route_after_gatekeeper(st_dropped_more) == "specifier")
check("route_after_gatekeeper done->END", pl.route_after_gatekeeper(st_done) == str(END) or pl.route_after_gatekeeper(st_done) == END)
check("route_after_fixer queue->specifier",
      pl.route_after_fixer({"findings": [{}]}) == "specifier")
check("route_after_fixer empty->END", pl.route_after_fixer({"findings": []}) == END)

# graph topology compiles with the new fixer conditional edges
full_app = pl.build_godel_graph()
check("build_godel_graph compiles with new routes", full_app is not None)

print("== Reporting honesty ==")
cls_safe = pl._classify_terminal_state({"verified_bugs": [], "findings": [],
    "hunter_parse_error": None, "supervisor_runs": 1, "supervisor_critique": None,
    "executor_runs": 1, "z3_result": {"status": "unsat"}})
check("UNSAT reported as proven safe", cls_safe.startswith("verified mathematically safe"))
cls_abort = pl._classify_terminal_state({"verified_bugs": [], "findings": [],
    "hunter_parse_error": None, "supervisor_runs": 3, "supervisor_critique": "still bad",
    "executor_runs": 1, "z3_result": {"status": "unsat"}})
check("supervisor-limit abort NOT reported as safe", "aborted" in cls_abort)
cls_parse = pl._classify_terminal_state({"verified_bugs": [], "findings": [],
    "hunter_parse_error": "bad json", "supervisor_runs": 0, "supervisor_critique": None,
    "executor_runs": 0, "z3_result": None})
check("parse failure NOT reported as safe", "analysis_failed" in cls_parse)
cls_exec = pl._classify_terminal_state({"verified_bugs": [], "findings": [],
    "hunter_parse_error": None, "supervisor_runs": 1, "supervisor_critique": None,
    "executor_runs": 4, "z3_result": {"status": "error"}})
check("executor exhaustion reported inconclusive", "inconclusive" in cls_exec)

print("== C4: requirements.txt ==")
req = (PROJECT_ROOT / "requirements.txt").read_text(encoding="utf-8")
for dep in ("psycopg2-binary", "httpx", "sentence-transformers", "fastmcp"):
    check(f"C4 requirements pins {dep}", dep in req)

print("\n========================")
print(f"PASSED: {len(PASS)}  FAILED: {len(FAIL)}")
if FAIL:
    print("Failures:", *FAIL, sep="\n  - ")
    sys.exit(1)
