"""
Regression tests for the second batch of audit fixes (tooling, parsers,
infrastructure, concurrency, MCP transport, hygiene).
No network / API keys / DB required.
Run:  python testOfCode/test_remaining_fixes.py
"""
import io
import json
import os
import sys
import tempfile
import threading
import xml.etree.ElementTree as ET
from concurrent.futures import Future
from pathlib import Path
from unittest.mock import patch

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


print("== Config timeouts ==")
from domain import config
check("config.Z3_TIMEOUT_SECONDS exists", isinstance(config.Z3_TIMEOUT_SECONDS, float))
check("config.FORGE_TIMEOUT_SECONDS exists", isinstance(config.FORGE_TIMEOUT_SECONDS, float))
import domain.z3_runner as zr
check("z3_runner reads config timeout", "config.Z3_TIMEOUT_SECONDS" in Path(zr.__file__).read_text())

print("== Tightened compile-failure heuristic ==")
from domain.gatekeeper import FoundryGatekeeper, is_compile_failure, has_executed_tests
check("tests-ran detection ('Ran 2 tests')", has_executed_tests("Ran 2 tests: ..."))
check("compile failure detected", is_compile_failure("Compiler run failed", ""))
check("runtime 'Error (' with tests ran NOT compile failure",
      not is_compile_failure("[Revert] Error (panic): 0x11\nRan 2 tests", "[FAIL.] t()"))
check("solc ParserError without tests IS compile failure",
      is_compile_failure("ParserError: expected ;", ""))

gate = FoundryGatekeeper(project_root=str(PROJECT_ROOT), verifier_agent=None,
                         debug_dir=str(PROJECT_ROOT / "output" / "debug_tests"))

def fake_run_factory(returncode, stdout, stderr=""):
    import subprocess as sp
    cp = type("CP", (), {})()
    cp.returncode = returncode
    cp.stdout = stdout
    cp.stderr = stderr
    def _f(*a, **k):
        return cp
    return _f

with patch.object(__import__("domain.gatekeeper", fromlist=["subprocess"]).subprocess, "run",
                  fake_run_factory(1, "Ran 1 test.\ninternal forge panic: OOM\nError (panic)")):
    status, _ = gate.execute_qc_validation("// t", max_retries=1, debug_tag="t2_runtime_revert")
check("C3b runtime-revert crash -> inconclusive (no heal loop)", status == "inconclusive", f"got {status}")

with patch.object(__import__("domain.gatekeeper", fromlist=["subprocess"]).subprocess, "run",
                  fake_run_factory(1, "", "Compiler run failed:\nTypeError: ...")):
    status, _ = gate.execute_qc_validation("// t", max_retries=1, debug_tag="t2_compile")
check("compile failure -> compile_failed", status == "compile_failed", f"got {status}")

print("== Contract-name extraction + src/ cleanup ==")
src_multi = """// contract FakeInComment
interface IThing { }
abstract contract BaseImpl {}
library L {}
contract RealTarget is BaseImpl {}"""
check("extract skips comments/abstract, finds concrete contract",
      FoundryGatekeeper.extract_contract_name(src_multi, fallback="stem") == "RealTarget")
src_pref = "interface MyToken {}\ncontract MyToken is IMyToken {}"
check("extract prefers stem match over earlier contract",
      FoundryGatekeeper.extract_contract_name(src_pref, fallback="MyToken") == "MyToken")
check("extract falls back when no concrete contract",
      FoundryGatekeeper.extract_contract_name("interface Only {}", fallback="Fallback") == "Fallback")

mat_path = gate.materialize_source("// probe", "ProbeContract")
check("materialize creates src file", Path(mat_path).exists())
gate.cleanup_source(mat_path)
check("cleanup removes src file", not Path(mat_path).exists())

print("== validate_finding wired ==")
from domain.schema import build_finding, validate_finding
built = build_finding(
    {"target_function": "f", "severity_guess": "high", "intent": "i", "constraint": "c", "relevant_code": "r"},
    {"contract_name": "K", "z3_code": "", "z3_result": None, "iterations": 0},
    "", "", "", "confirmed")
check("build_finding passes validation", validate_finding(built) == [])

print("== llm_utils retry policy ==")
from domain.llm_utils import call_with_retry

class ApiErr(Exception):
    def __init__(self, status=None, headers=None):
        self.status_code = status
        if headers is not None:
            self.response = type("R", (), {"headers": headers})()

sleeps = []
sleeper = lambda s: sleeps.append(s)

calls = []
def auth_fail():
    calls.append(1)
    raise ApiErr(status=401)
try:
    call_with_retry(auth_fail, attempts=5, sleep_fn=sleeper)
    check("401 fails fast", False)
except ApiErr:
    check("401 fails fast (no retries)", len(calls) == 1 and sleeps == [])
    calls.clear(); sleeps.clear()

def server_err():
    calls.append(1)
    if len(calls) < 3:
        raise ApiErr(status=503)
    return "ok"
result = call_with_retry(server_err, attempts=5, backoff=2, sleep_fn=sleeper)
check("503 retries then succeeds", result == "ok" and len(calls) == 3)
check("backoff has jitter (> base)", all(s >= 1 for s in sleeps) and any(s > 1 for s in sleeps),
      f"sleeps={sleeps}")
calls.clear(); sleeps.clear()

def rate_limited():
    calls.append(1)
    raise ApiErr(status=429, headers={"retry-after": "7"})
try:
    call_with_retry(rate_limited, attempts=2, sleep_fn=sleeper)
except ApiErr:
    check("Retry-After honoured exactly", sleeps == [7.0], f"sleeps={sleeps}")

calls.clear(); sleeps.clear()
def ctx_len():
    calls.append(1)
    raise Exception("This model's maximum context length is 8192 tokens")
try:
    call_with_retry(ctx_len, attempts=5, sleep_fn=sleeper)
    check("context-length fails fast", False)
except Exception:
    check("context-length fails fast", len(calls) == 1)

print("== postgres.embed hardening ==")
import Infrastructure.postgres as pg

class FakeResp:
    def __init__(self, payload, status_error=None):
        self._payload = payload
        self._err = status_error
    def raise_for_status(self):
        if self._err:
            raise self._err
    def json(self):
        return self._payload

import httpx
req = httpx.Request("POST", pg.OLLAMA_URL)
resp500 = httpx.Response(500, request=req, text="boom")

with patch.object(pg.httpx, "post", lambda *a, **k: FakeResp({"embeddings": [[0.1] * 2500]})):
    vec = pg.embed("hello")
check("embed success truncates to 2000 dims", len(vec) == 2000)

def post_500(*a, **k):
    r = FakeResp(None)
    r.raise_for_status()
    return r
# simulate raise_for_status raising HTTPStatusError
class Resp500:
    def raise_for_status(self):
        raise httpx.HTTPStatusError("err", request=req, response=resp500)
with patch.object(pg.httpx, "post", lambda *a, **k: Resp500()):
    try:
        pg.embed("hello")
        check("HTTP 500 -> clear RuntimeError", False)
    except RuntimeError as e:
        check("HTTP 500 -> clear RuntimeError", "HTTP 500" in str(e))

with patch.object(pg.httpx, "post", lambda *a, **k: FakeResp({"error": "model 'x' not found"})):
    try:
        pg.embed("hello")
        check("Ollama error payload -> RuntimeError", False)
    except RuntimeError as e:
        check("Ollama error payload -> RuntimeError", "not found" in str(e))

# connection closed even when embed blows up
class FakeConn:
    closed_called = False
    def cursor(self, **k): raise AssertionError("should not be reached")
    def close(self): self.closed_called = True

fake_conn = FakeConn()
with patch.object(pg.psycopg2, "connect", lambda **k: fake_conn), \
     patch.object(pg, "embed", lambda q: (_ for _ in ()).throw(RuntimeError("ollama down"))):
    try:
        pg.retrieve(["q1"])
        check("retrieve propagates embed failure", False)
    except RuntimeError:
        pass
check("connection closed on embed failure", fake_conn.closed_called)

print("== piyoxml parser fixes ==")
import importlib
importlib.reload(sys.modules["piyoxml"]) if "piyoxml" in sys.modules else None
from piyoxml import parse_solidity_to_xml

SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Hook {
    mapping(address => uint256) balances;
    // function-type STATE VARIABLE must stay in state_variables:
    function(uint256) external returns (uint256) computeHook;
    function withdraw(uint256 amt) public {
        require(balances[msg.sender] >= amt);
        if (amt > 0 && balances[msg.sender] >= amt) {
            emit Done(a[b[c]]>=amt);
        }
    }
    event Done(uint256 x);
}
"""
tmp_sol = Path(tempfile.mkdtemp()) / "Hook.sol"
tmp_sol.write_text(SOL, encoding="utf-8")
xml_str = parse_solidity_to_xml(str(tmp_sol))
check("parse succeeds", bool(xml_str))
try:
    ET.fromstring(xml_str)
    check("output is valid XML (CDATA-safe with ]]> literal)", True)
except ET.ParseError as e:
    check("output is valid XML (CDATA-safe with ]]> literal)", False, str(e))
sv_match = [m for m in __import__("re").findall(r"<state_variables>(.*?)</state_variables>", xml_str, __import__("re").DOTALL)]
state_block = sv_match[0] if sv_match else ""
check("function-type state var kept in state_variables", "computeHook" in state_block)
fn_names = __import__("re").findall(r'<function name="([^"]+)"', xml_str)
check("state var NOT carved out as function", "computeHook" not in fn_names, f"fns={fn_names}")

from domain.pipeline import extract_functions_from_xml, extract_element_text, _strip_cdata
funcs = extract_functions_from_xml(xml_str)
wd = [f for f in funcs if f["name"] == "withdraw"]
check("withdraw extracted with ]]>= expression intact",
      bool(wd) and "a[b[c]]>=amt" in wd[0]["body"], f"body={wd[0]['body'][:200] if wd else 'MISSING'}")
check("_strip_cdata unescapes ]]> correctly",
      _strip_cdata("<![CDATA[a[b[c]]]]><![CDATA[>=x]]>") == "a[b[c]]>=x")

print("== piyoxml CLI guard ==")
proc_out = __import__("subprocess").run([sys.executable, "piyoxml.py"], capture_output=True,
                                        text=True, cwd=str(PROJECT_ROOT))
check("no NameError on bare invocation", proc_out.returncode != 0 and "NameError" not in proc_out.stderr)

print("== Prompt loads use utf-8 ==")
pg_src = Path("domain/propertygenerator.py").read_text(encoding="utf-8")
cg_src = Path("domain/cegis.py").read_text(encoding="utf-8")
check("propertygenerator utf-8", 'encoding="utf-8"' in pg_src)
check("cegis utf-8", 'encoding="utf-8"' in cg_src)

print("== Pipeline: folder validation ==")
from domain.pipeline import run_pipeline, _collect_future_result, _classify_terminal_state
for bad in ("", "definitely_not_a_real_folder_xyz"):
    try:
        run_pipeline(bad)
        check(f"run_pipeline('{bad or '<empty>'}') fails loudly", False)
    except SystemExit as e:
        check(f"run_pipeline('{bad or '<empty>'}') fails loudly", True)

print("== Pipeline: timeout future salvage ==")
results = []
done_future = Future()
done_future.set_result({"current_focus_function": "lateFn", "verified_bugs": [
    {"finding": {"target_function": "lateFn", "intent": "bug"}, "fix_code": "",
     "poc_test_code": "", "forge_output": "", "qc_status": "confirmed"}],
    "rag_diagnostics": {}})
_collect_future_result(done_future, "lateFn", "Stem", results)
check("salvage collects late-finished results", len(results) == 1 and results[0]["function"] == "lateFn")

print("== fixer_node copy-on-write ==")
import domain.graph_nodes as gn

class FakeFixerAgent:
    def generate_remediation(self, finding, state):
        return "fixed; // code"

from domain.formatter import SubmissionFormatter
gn_config_backup = gn.config.SUBMISSIONS_FOLDER
tmp_sub = Path(tempfile.mkdtemp())
try:
    gn.config.SUBMISSIONS_FOLDER = tmp_sub
    bug = {"finding": {"target_function": "fnA", "intent": "i", "constraint": "c",
                       "relevant_code": "r", "severity_guess": "high"},
           "z3_result": None, "bug_report": "rep", "poc_test_code": "//",
           "forge_output": "//", "qc_status": "confirmed"}
    st = {"verified_bugs": [bug], "contract_name": "K", "z3_code": "z3code",
          "findings": [{"id": 2}], "mode": ""}
    upd = gn.fixer_node(st, FakeFixerAgent(), SubmissionFormatter())
    check("original bug dict NOT mutated", "fix_code" not in bug)
    check("returned bugs carry fix_code", upd["verified_bugs"][-1].get("fix_code") == "fixed; // code")
    check("queued findings preserved through fixer", upd.get("findings", [{}]) != [] and st["findings"])
    wrote = list(tmp_sub.rglob("finding.json"))
    check("submission files written to unique folder", len(wrote) == 1 and "_" in wrote[0].parent.name)
finally:
    gn.config.SUBMISSIONS_FOLDER = gn_config_backup

print("== Gatekeeper node cleans up src/ ==")
src_before = set((PROJECT_ROOT / "src").glob("*.sol"))
class FakeVerifierAgent:
    def generate_test_suite(self, *a):
        return "// fake test"
class FakeGK:
    verifier_agent = FakeVerifierAgent()
    def is_finding_in_scope(self, finding, state):
        return True
    def materialize_source(self, code, name):
        return gate.materialize_source(code, name)
    def cleanup_source(self, p):
        gate.cleanup_source(p)
    def execute_qc_validation(self, code, **k):
        return "property_held", "out"
st_gk = {"findings": [{"target_function": "fnZ", "intent": "clean intent here",
                       "constraint": "c", "relevant_code": "r", "severity_guess": "low",
                       "class": "isolated"}],
         "user_contract": "contract Zed {}\n", "contract_name": "Zed",
         "verified_bugs": [], "bug_report": "rep", "z3_result": None}
upd_gk = gn.gatekeeper_node(st_gk, FakeGK())
src_after = set((PROJECT_ROOT / "src").glob("*.sol"))
check("src/ left clean after gatekeeper run", src_after == src_before,
      f"new={[p.name for p in src_after - src_before]}")

print("== MCP stdio protection ==")
from mcp_server import _stdout_to_stderr
r_out, w_out = os.pipe()
r_err, w_err = os.pipe()
saved1, saved2 = os.dup(1), os.dup(2)
os.dup2(w_out, 1)
os.dup2(w_err, 2)
try:
    with _stdout_to_stderr():
        print("PIPELINE_NOISE_LINE")
        sys.stdout.flush()
    print("JSONRPC_FRAME")
    sys.stdout.flush()
finally:
    os.dup2(saved1, 1); os.close(saved1)
    os.dup2(saved2, 2); os.close(saved2)
    os.close(w_out); os.close(w_err)
out_txt = os.read(r_out, 65536).decode()
err_txt = ""
while True:
    chunk = os.read(r_err, 65536)
    if not chunk:
        break
    err_txt += chunk.decode()
os.close(r_out); os.close(r_err)
check("pipeline prints routed to stderr during tool call", "PIPELINE_NOISE_LINE" in err_txt,
      f"err={err_txt[:200]!r}")
check("stdout restored for JSON-RPC frames", "JSONRPC_FRAME" in out_txt, f"out={out_txt[:200]!r}")
check("fd1 restored to original", os.dup(1) is not None)

print("== Hygiene ==")
check("orphaned arbiter.pyc removed",
      not (PROJECT_ROOT / "domain/__pycache__/arbiter.cpython-314.pyc").exists())
check("broken stale tests quarantined",
      (PROJECT_ROOT / "testOfCode/stale/test.py").exists()
      and not (PROJECT_ROOT / "testOfCode/test.py").exists())

print("\n========================")
print(f"PASSED: {len(PASS)}  FAILED: {len(FAIL)}")
if FAIL:
    print("Failures:", *FAIL, sep="\n  - ")
    sys.exit(1)
