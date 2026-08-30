import os
import re
import sys
import json
import logging
import tempfile
import traceback
import concurrent.futures
import xml.etree.ElementTree as ET
from pathlib import Path

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.messages import AIMessage
from langgraph.graph import StateGraph, END

from piyoxml import parse_solidity_to_xml
from domain import config
from domain.abstracter import abstract_contract, render_cfg_slice
from domain.semantics import generate_harness
from domain.inspector import Inspector
from domain.propertygenerator import PropertyGenerator
from domain.cegis import CEGIS
from domain.gatekeeper import FoundryGatekeeper
from domain.fixer import FixerAgent
from domain.formatter import SubmissionFormatter
from domain.verifier import PropertyVerifierAgent
from domain.state import GraphState
from domain.graph_nodes import (
    supervisor_node,
    bug_hunter_node,
    specifier_node,
    executor_node,
    gatekeeper_node,
    fixer_node,
)
from domain.z3_runner import run_z3
from domain.schema import build_finding, normalize_counterexample
from Infrastructure.postgres import warmup_rag

sys.stdout.reconfigure(encoding='utf-8')
load_dotenv(config.PROJECT_ROOT / ".env")
config.setup_logging()

logger = logging.getLogger(__name__)

# ==========================================
# CONFIGURATION
# ==========================================
for _folder in (config.XML_OUTPUT_FOLDER, config.FINDINGS_FOLDER, config.REPORTS_FOLDER,
                config.PROOFS_FOLDER, config.FIXES_FOLDER, config.SUBMISSIONS_FOLDER):
    os.makedirs(_folder, exist_ok=True)


# ==========================================
# LLM CLIENTS & AGENT INITIALIZATION
# ==========================================
llm_flash = ChatOpenAI(
    model="deepseek-v4-flash",
    openai_api_key=os.environ.get("DEEPSEEK_API_KEY"),
    temperature=0.0,
    openai_api_base="https://api.deepseek.com",
    extra_body={"thinking": {"type": "disabled"}},
    timeout=120,
    max_retries=5,
)

llm_pro = ChatOpenAI(
    model="deepseek-v4-flash",
    openai_api_key=os.environ.get("DEEPSEEK_API_KEY"),
    temperature=0.0,
    max_tokens=24000,
    openai_api_base="https://api.deepseek.com",
    extra_body={"thinking": {"type": "enabled", "budget_tokens": 16000}},
    timeout=120,
    max_retries=5,
)

# Isolator client: overridable to a fast model (GODEL_ISOLATOR_MODEL) since
# its proposals are machine-verified downstream. Falls back to llm_pro.
llm_isolator = (
    ChatOpenAI(
        model=config.ISOLATOR_MODEL,
        openai_api_key=os.environ.get("DEEPSEEK_API_KEY"),
        temperature=0.0,
        max_tokens=24000,
        openai_api_base="https://api.deepseek.com",
        extra_body={"thinking": {"type": "disabled"}},
        timeout=120,
        max_retries=5,
    )
    if config.ISOLATOR_MODEL else llm_pro
)

# Supervisor: a cheap JSON classifier whose routing verdict is ALWAYS
# re-verified by the Z3 solver and the Foundry gatekeeper downstream. A fast
# model with thinking off + structured JSON output is sufficient; this turns a
# multi-minute reasoner call into seconds for every finding-bearing function.
llm_supervisor = ChatOpenAI(
    model="deepseek-v4-flash",
    openai_api_key=os.environ.get("DEEPSEEK_API_KEY"),
    temperature=0.0,
    max_tokens=1200,
    openai_api_base="https://api.deepseek.com",
    extra_body={"thinking": {"type": "disabled"}},
    model_kwargs={"response_format": {"type": "json_object"}},
    timeout=120,
    max_retries=5,
)

# Repair/heal agent: fixes Z3 scripts and Foundry test suites whose errors are
# deterministically re-validated (Z3 re-run / solc compile) before anything is
# accepted — a fast model is sufficient for these mechanical repairs.
llm_repair = ChatOpenAI(
    model="deepseek-v4-flash",
    openai_api_key=os.environ.get("DEEPSEEK_API_KEY"),
    temperature=0.0,
    max_tokens=24000,
    openai_api_base="https://api.deepseek.com",
    extra_body={"thinking": {"type": "disabled"}},
    timeout=120,
    max_retries=5,
)

# Fixer: still a reasoning model (remediation-patch quality matters) but with a
# halved thinking budget — the fix runs AFTER the bug is Z3/forge-verified, so
# it is report content, not a verification gate. Cuts the slowest node on the
# finding path from ~4 min to ~2 min without touching soundness.
llm_fixer = ChatOpenAI(
    model="deepseek-v4-flash",
    openai_api_key=os.environ.get("DEEPSEEK_API_KEY"),
    temperature=0.0,
    max_tokens=24000,
    openai_api_base="https://api.deepseek.com",
    extra_body={"thinking": {"type": "enabled", "budget_tokens": 16000}},
    timeout=120,
    max_retries=5,
)

inspector = Inspector(llm_isolator, llm_pro)
generator = PropertyGenerator(agent=llm_flash)
property_verifier = PropertyVerifierAgent(agent_llm=llm_pro, heal_llm=llm_repair)
gatekeeper = FoundryGatekeeper(project_root=str(config.FOUNDRY_ROOT), verifier_agent=property_verifier)
fixer = FixerAgent(agent=llm_fixer)
formatter = SubmissionFormatter()
# strict=True: LLM-generated property scripts must pass the structural
# quality lint (SANITY probe, s.add/s.check presence) before execution —
# degenerate scripts get rejected with repair feedback instead of producing
# vacuous "safe" verdicts. Harness/vacuity probes call run_z3 directly.
cegis = CEGIS(agent=llm_repair, run_z3_tool=lambda code: run_z3(code, strict=True))


# ==========================================
# HELPER FUNCTIONS
# ==========================================
def _strip_cdata(text: str) -> str:
    """XML-style CDATA extraction: walks section boundaries exactly like a
    real parser, so piyoxml.cdata()'s ']]]]><![CDATA[>' escaping round-trips
    back to the original ']]>' text (a naive global replace corrupts it)."""
    parts = []
    idx = 0
    while True:
        start = text.find("<![CDATA[", idx)
        if start == -1:
            parts.append(text[idx:])
            break
        parts.append(text[idx:start])
        end = text.find("]]>", start + 9)
        if end == -1:
            parts.append(text[start + 9:])
            break
        parts.append(text[start + 9:end])
        idx = end + 3
    return "".join(parts).strip()


def extract_element_text(xml_string: str, tag_name: str) -> str:
    """All text content under every occurrence of <tag_name>, CDATA decoded
    natively. Primary path uses a real XML parser (immune to literal
    '</tag>' sequences inside CDATA-wrapped Solidity strings that truncate
    the legacy regex mid-element); falls back to the regex walk only when
    the document is malformed."""
    root = _parse_audit_xml(xml_string)
    if root is not None:
        chunks = []
        for el in root.iter(tag_name):
            text = "".join(el.itertext()).strip()
            if text:
                chunks.append(text)
        return "\n".join(chunks)
    pattern = rf"<{tag_name}.*?>(.*?)</{tag_name}>"
    matches = re.findall(pattern, xml_string, re.DOTALL)
    cleaned = []
    for m in matches:
        c = _strip_cdata(m)
        if c:
            cleaned.append(c)
    return "\n".join(cleaned)


def extract_functions_from_xml(xml_string: str) -> list:
    root = _parse_audit_xml(xml_string)
    functions = []
    if root is not None:
        for el in root.iter("function"):
            name = el.get("name")
            body = "".join(el.itertext()).strip()
            if not name or "{" not in body:
                continue
            functions.append({"name": name, "body": body,
                              "container": el.get("container") or ""})
        return functions
    pattern = r'<function\s+name="([^"]+)"[^>]*>(.*?)</function>'
    matches = re.findall(pattern, xml_string, re.DOTALL)
    for name, body in matches:
        if "{" not in body:
            continue
        functions.append({"name": name, "body": _strip_cdata(body),
                          "container": ""})
    return functions


def scope_functions_to_primary_contract(functions: list, stem: str) -> tuple:
    """Restrict per-function fan-out to the file's primary contract.

    Flattened benchmarks inline library/interface/base stubs (SafeMath,
    Address, ...); auditing those wastes credits and yields stub-targeted
    false positives (Visor run 2026-08: 74 graphs, 60+ on stubs). Uses the
    piyoxml container attribute to keep only functions defined inside the
    primary contract. Falls back to the full list whenever scoping is
    ambiguous or would leave zero functions — never silently shrinks
    coverage. Returns (kept, excluded_names)."""
    containers = {f.get("container") for f in functions if f.get("container")}
    if not containers:
        return functions, []
    contract_containers = sorted(c for c in containers if c.startswith("contract "))
    target = None
    stem_l = str(stem or "").lower()
    for c in contract_containers:
        if c.split(" ", 1)[1].lower() == stem_l:
            target = c
            break
    if target is None and len(contract_containers) == 1:
        target = contract_containers[0]
    if target is None:
        return functions, []
    kept = [f for f in functions if f.get("container") == target]
    if not kept:
        return functions, []
    excluded = [f["name"] for f in functions if f.get("container") != target]
    return kept, excluded


def _parse_audit_xml(xml_string: str):
    """Returns the parsed root Element of piyoxml output, or None when the
    document is not well-formed (callers degrade to the legacy regex path
    instead of failing the audit — non-fatal by contract)."""
    try:
        return ET.fromstring(xml_string)
    except ET.ParseError:
        return None


def collect_sol_files(folder: str) -> list:
    # Absolute paths are mandatory here: domain.abstracter temporarily chdirs
    # the whole process into an isolated tmpdir while Slither runs, so any
    # thread resolving a relative path during that window would read from the
    # wrong directory.
    sol_files = []
    for root, _, files in os.walk(folder):
        for file in sorted(files):
            if file.endswith(".sol"):
                sol_files.append(os.path.abspath(os.path.join(root, file)))
    return sol_files


def batch_timeout_for(n_functions: int) -> float:
    """Wall-clock budget for one contract's parallel function graphs.

    Functions run MAX_WORKERS-at-a-time, so the budget scales with the
    number of sequential waves (ceil(n / workers)) rather than the raw
    function count — a per-function-times-count cap massively over-waits
    large contracts and delays the timeout-salvage path."""
    workers = max(1, config.MAX_WORKERS)
    waves = max(1, (max(0, int(n_functions)) + workers - 1) // workers)
    return config.PER_FUNCTION_TIMEOUT * waves


def is_read_only_function(analysis: dict | None, func_name: str) -> bool:
    """Deterministic fast-path predicate: True when the Slither abstraction
    shows the function cannot write storage, cannot call out, and is not
    payable — i.e. it cannot violate any storage-transition invariant the Z3
    harness models. Returns False whenever the analysis is unavailable or the
    function cannot be matched, so coverage only ever shrinks when we KNOW."""
    if not analysis:
        return False
    functions = analysis.get("functions", {})
    key = next(
        (k for k in functions if k.split("(", 1)[0] == func_name.split("(", 1)[0]),
        None,
    )
    if key is None:
        return False
    f = functions[key]
    return (
        not f.get("state_writes")
        and not f.get("has_external_call")
        and not f.get("payable")
    )


_TRANSIENT_MARKERS = (
    "connection", "getaddrinfo", "timeout", "timed out",
    "connectionerror", "connecterror", "reset by peer",
    # Rate limiting / capacity exhaustion — the other common transient class.
    # Without these, a burst of 429s during parallel function graphs kills the
    # analysis permanently instead of retrying after backoff.
    "429", "rate limit", "rate_limit", "ratelimit", "too many requests",
    "quota", "overloaded", "server overload", "capacity",
    "502", "503", "bad gateway", "service unavailable", "server error",
)


def _is_transient_error(exc: Exception) -> bool:
    """True when the exception looks like a transient infrastructure failure
    (network or provider rate limiting) worth retrying, False for logic bugs."""
    exc_text = str(exc).lower()
    return any(marker in exc_text for marker in _TRANSIENT_MARKERS)


def process_function(func, raw_solidity_code, stem, readme, env_setup, interfaces, state_vars, app,
                     static_analysis=None):
    import time as _time
    func_name = func['name']
    max_function_retries = config.FUNCTION_MAX_RETRIES
    for attempt in range(max_function_retries + 1):
        try:
            return _process_function_inner(func, raw_solidity_code, stem, readme, env_setup,
                                           interfaces, state_vars, app, static_analysis)
        except Exception as exc:
            if _is_transient_error(exc) and attempt < max_function_retries:
                delay = 5.0 * (attempt + 1)
                print(f"      [FUNCTION RETRY] {func_name} failed with transient error "
                      f"({type(exc).__name__}). Retrying in {delay}s "
                      f"(attempt {attempt + 1}/{max_function_retries})...")
                _time.sleep(delay)
                continue
            raise


def _process_function_inner(func, raw_solidity_code, stem, readme, env_setup, interfaces, state_vars, app,
                     static_analysis=None):
    print(f"  -> Spawning Graph Thread for [{func['name']}]...")

    cfg_block = ""
    harness = None
    if static_analysis and not config.is_dry_run():
        cfg_block = render_cfg_slice(static_analysis, func["name"])
        if cfg_block:
            print(f"      [ABSTRACTER] CFG slice attached for {func['name']} ({len(cfg_block)} chars)")
        harness = generate_harness(static_analysis, func["name"])
        if harness:
            print(f"      [SEMANTICS] deterministic model ready for {func['name']} "
                  f"(quality={harness['quality']}, untranslated={len(harness['untranslated'])})")

    injection_packet = f"""<analysis_packet>
    <environment_wiring>
        <setup>{env_setup}</setup>
        <interfaces>{interfaces}</interfaces>
        <global_storage_slots>{state_vars}</global_storage_slots>
    </environment_wiring>
{cfg_block}
    <target_isolated_function>
{func['body']}
    </target_isolated_function>
</analysis_packet>"""

    initial_state = {
        "user_contract": raw_solidity_code,
        "contract_name": stem,
        "readme_specs": readme,
        "messages": [],
        "next_agent": "bug_hunter",
        "current_focus_function": func["name"],
        "supervisor_critique": None,
        "mode": "",
        "intent": "",
        "queries": [],
        "findings": [],
        "verified_bugs": [],
        "z3_code": "",
        "z3_result": None,
        "slither_result": static_analysis,
        "semantic_harness": harness,
        "model_quality": harness["quality"] if harness else None,
        "bug_report": None,
        "iterations": 0,
        "supervisor_runs": 0,
        "executor_runs": 0,
        "hunter_retries": 0,
        "poc_test_code": "",
        "forge_output": "",
        "qc_status": "",
        "isolated_xml_packet": injection_packet,
    }

    return app.invoke(initial_state)


# ==========================================
# NODE WRAPPERS
# ==========================================
def node_supervisor(state: GraphState): return supervisor_node(state, llm_supervisor)


def node_bug_hunter(state: GraphState):
    if config.is_dry_run():
        return {
            "findings": [],
            "messages": [AIMessage(content="[DRY-RUN]: bug_hunter mocked, no LLM calls made.")],
        }
    return bug_hunter_node(state, inspector)


def node_specifier(state: GraphState): return specifier_node(state, generator)
def node_executor(state: GraphState): return executor_node(state, cegis)
def node_gatekeeper(state: GraphState): return gatekeeper_node(state, gatekeeper)
def node_fixer(state: GraphState): return fixer_node(state, fixer, formatter)


# ==========================================
# GRAPH ROUTING LOGIC (Escalation Pipeline)
# ==========================================
def route_after_hunter(state: GraphState) -> str:
    if state.get("hunter_parse_error") and not state.get("findings"):
        # Unparseable Isolator output must never masquerade as 'safe', and it
        # should not dead-end either — retry bounded by hunter_retries.
        if state.get("hunter_retries", 0) < config.HUNTER_MAX_PARSE_RETRIES:
            print(f"      [ROUTING] Hunter output unparseable — retrying "
                  f"({state.get('hunter_retries', 0) + 1}/{config.HUNTER_MAX_PARSE_RETRIES})")
            return "bug_hunter"
        print("      [ROUTING] Hunter retries exhausted — aborting as analysis_failed.")
        return END
    if not state.get("findings"):
        print(f"      [BUG HUNTER] No vulnerabilities detected in {state.get('current_focus_function')}. Exiting early.")
        return END
    return "supervisor"


def route_after_supervisor(state: GraphState) -> str:
    critique = state.get("supervisor_critique")
    if state.get("supervisor_runs", 0) >= config.SUPERVISOR_MAX_ITERATIONS:
        print(f"      [GRAPH ABORT] Supervisor loop limit reached for {state.get('current_focus_function')}.")
        return END
    if critique:
        return "bug_hunter"
    return "specifier"


def route_after_specifier(state: GraphState) -> str:
    # A critique left over from an Executor Z3 error is repair feedback for the
    # specifier itself — do NOT detour through the supervisor (that would burn
    # SUPERVISOR_MAX_ITERATIONS slots and can restart the whole hunter loop).
    res = state.get("z3_result", {}) or {}
    last_status = res.get("status")
    if state.get("supervisor_critique") and last_status not in ("error", "inconclusive", "vacuous"):
        return "supervisor"
    return "executor"


def route_after_executor(state: GraphState) -> str:
    res = state.get("z3_result", {}) or {}
    status = res.get("status")
    if status in ("error", "inconclusive", "vacuous"):
        # inconclusive = script ran but printed no unambiguous verdict sentinel;
        # vacuous = SANITY probe failed (over-constrained base model). Neither
        # is a verdict — all need a regenerated/refined property.
        if state.get("executor_runs", 0) >= config.EXECUTOR_MAX_ITERATIONS:
            return END
        return "specifier"
    elif status == "sat":
        return "gatekeeper"
    if state.get("findings"):
        return "specifier"
    return END


def route_after_gatekeeper(state: GraphState) -> str:
    if state.get("verified_bugs"):
        return "fixer"
    if state.get("findings"):
        # Current finding was dropped (out of scope / false positive) but more
        # findings are queued for this function — keep verifying them.
        return "specifier"
    return END


def route_after_fixer(state: GraphState) -> str:
    if state.get("findings"):
        # More queued findings for this function remain after a successful
        # remediation cycle.
        return "specifier"
    return END


def build_godel_graph():
    workflow = StateGraph(GraphState)

    workflow.add_node("supervisor", node_supervisor)
    workflow.add_node("bug_hunter", node_bug_hunter)
    workflow.add_node("specifier", node_specifier)
    workflow.add_node("executor", node_executor)
    workflow.add_node("gatekeeper", node_gatekeeper)
    workflow.add_node("fixer", node_fixer)

    workflow.add_conditional_edges(
        "bug_hunter",
        route_after_hunter,
        {"supervisor": "supervisor", "bug_hunter": "bug_hunter", END: END},
    )

    workflow.add_conditional_edges(
        "supervisor",
        route_after_supervisor,
        {"bug_hunter": "bug_hunter", "specifier": "specifier", END: END},
    )

    workflow.add_conditional_edges(
        "specifier",
        route_after_specifier,
        {"supervisor": "supervisor", "executor": "executor"},
    )

    workflow.add_conditional_edges(
        "executor",
        route_after_executor,
        {"specifier": "specifier", "gatekeeper": "gatekeeper", END: END},
    )

    workflow.add_conditional_edges(
        "gatekeeper",
        route_after_gatekeeper,
        {"fixer": "fixer", "specifier": "specifier", END: END},
    )

    workflow.add_conditional_edges(
        "fixer",
        route_after_fixer,
        {"specifier": "specifier", END: END},
    )

    workflow.set_entry_point("bug_hunter")

    return workflow.compile()


# ==========================================
# THE ENGINE
# ==========================================
def _timeout_finding(contract_name: str, func_name: str) -> dict:
    return build_finding(
        {"target_function": func_name, "severity_guess": "info", "intent": "Analysis timed out"},
        {"contract_name": contract_name, "z3_code": "", "z3_result": None, "iterations": 0},
        "", "", "", "timeout",
    )


def _error_finding(contract_name: str, func_name: str, exc: Exception) -> dict:
    """Visible artifact for a function whose analysis graph RAISED. Without
    this, exceptions made functions silently vanish from the report — the
    exact failure mode that dropped findings in the PoolTogether M-01 case."""
    detail = str(exc)[:300]
    return build_finding(
        {"target_function": func_name, "severity_guess": "info",
         "intent": f"Analysis failed ({type(exc).__name__}): {detail}. "
                   f"This function was NOT verified — treat as unanalyzed."},
        {"contract_name": contract_name, "z3_code": "", "z3_result": None, "iterations": 0},
        "", "", "", "graph_error",
    )


def _incomplete_finding(contract_name: str, func_name: str, reason: str) -> dict:
    """Visible artifact for analyses that aborted without a final verdict
    (retries exhausted, unparseable hunter output, vacuous proof, unresolved
    findings still queued). Distinguishes 'we could not finish' from 'safe'."""
    return build_finding(
        {"target_function": func_name, "severity_guess": "info",
         "intent": f"Analysis incomplete — {reason}. NOT a safety verdict."},
        {"contract_name": contract_name, "z3_code": "", "z3_result": None, "iterations": 0},
        "", "", "", "analysis_incomplete",
    )


def _should_flag_incomplete(final_state: dict) -> str | None:
    """Returns a human-readable reason string when the terminal graph state
    represents an aborted/incomplete analysis rather than a genuine verdict,
    else None. Ironclad guarantee: results contain only verified bugs,
    proven-safe verdicts, or explicit incomplete/error artifacts."""
    if final_state.get("hunter_parse_error") and not final_state.get("findings"):
        return "bug hunter output remained unparseable after retries"
    if final_state.get("findings"):
        return f"{len(final_state['findings'])} proposed finding(s) left unprocessed when the graph aborted"
    res = final_state.get("z3_result", {}) or {}
    if (final_state.get("executor_runs", 0) >= config.EXECUTOR_MAX_ITERATIONS
            and res.get("status") in ("error", "inconclusive", "vacuous")):
        return f"executor exhausted {config.EXECUTOR_MAX_ITERATIONS} retries without a verdict"
    if final_state.get("vacuity_status") == "vacuous":
        return f"UNSAT verdict was vacuous ({final_state.get('vacuity_reason', 'model unreachable')})"
    if res.get("status") == "vacuous":
        return "base model was over-constrained (SANITY probe UNSAT) — no real verdict produced"
    return None


def _classify_terminal_state(final_state: dict) -> str:
    """Distinguishes a genuine UNSAT-proven 'safe' verdict from aborts and
    analysis failures — they must never be conflated in reporting."""
    if final_state.get("hunter_parse_error"):
        return "analysis_failed (Isolator output unparseable) — NOT proven safe"
    if final_state.get("verified_bugs"):
        return f"{len(final_state['verified_bugs'])} verified bug(s)"
    if final_state.get("findings"):
        return "aborted with unresolved findings queued"
    if (final_state.get("supervisor_runs", 0) >= config.SUPERVISOR_MAX_ITERATIONS
            and final_state.get("supervisor_critique")):
        return f"aborted: supervisor limit reached ({config.SUPERVISOR_MAX_ITERATIONS}) — review pending critique"
    res = final_state.get("z3_result", {}) or {}
    if (final_state.get("executor_runs", 0) >= config.EXECUTOR_MAX_ITERATIONS
            and res.get("status") in ("error", "inconclusive")):
        return f"aborted: executor exhausted retries on Z3 errors — inconclusive, NOT proven safe"
    if final_state.get("vacuity_status") == "vacuous":
        return f"vacuously safe (UNSAT but {final_state.get('vacuity_reason', 'model unreachable')}) — NOT a real proof"
    if res.get("status") == "unsat":
        # Honest labeling: the strength of the claim must reflect the strength
        # of the model that produced it.
        quality = final_state.get("model_quality")
        if quality == "FULL":
            return "verified safe (UNSAT · exact deterministic static-analysis model)"
        if quality == "PARTIAL":
            return "safe under over-approximated model (UNSAT · partial static encoding)"
        return "verified mathematically safe (UNSAT)"
    if res.get("status") in ("error", "inconclusive"):
        return "inconclusive: Z3 never produced an unambiguous verdict"
    return "ended without verification (no Z3 verdict recorded)"


def _discovery_finding(stem: str, broken: dict) -> dict:
    """Adapts a machine-verified broken invariant (discovery phase) into the
    same FindingSchema shape the graph pipeline produces, so compositional
    results land in the main audit summary/submission like any verified bug."""
    violated = broken.get("violated_by") or ["contract-level"]
    func = violated[0]
    cex = {}
    for c in broken.get("counterexamples", []):
        if c.get("function") == func and c.get("assignments"):
            cex = c["assignments"]
            break
    if not cex and broken.get("counterexamples"):
        cex = broken["counterexamples"][0].get("assignments", {})

    finding = {
        "target_function": func,
        # MEDIUM, not HIGH: the violation is machine-proven, but the invariant
        # itself is LLM-proposed — a junk proposal slipping past the filter
        # would otherwise surface as a HIGH false positive.
        "severity_guess": "medium",
        "intent": (f"Contract invariant broken: '{broken['invariant']}' — violated by "
                   f"{', '.join(violated)} with a machine-found concrete counterexample "
                   f"(Z3 induction step over the deterministic static-analysis model)"),
        "constraint": broken["invariant"],
        "relevant_code": broken["invariant"],
    }
    state = {"contract_name": stem, "z3_code": "", "z3_result": None, "iterations": 0}
    built = build_finding(finding, state, "", "", "", "broken_invariant")
    built["counterexample"] = normalize_counterexample(cex)
    built["metadata"]["status"] = "broken_invariant"
    built["metadata"]["source"] = "discovery"
    built["metadata"]["violated_by"] = violated
    return built


def _run_discovery_phase(stem: str, static_analysis: dict) -> list:
    """Phase C (compositional): one fast LLM call proposes contract-wide
    invariants from STATIC FACTS only; Z3 proves/refutes each across ALL
    public functions locally (zero further credits). Broken invariants become
    schema-shaped findings merged into the main results list; the full report
    lands in output/reports/."""
    from domain.discovery import discover_invariants, default_discovery_llm

    print(f"\n=== DISCOVERY PHASE: {stem} (compositional invariant sweep) ===")
    result = discover_invariants(static_analysis, default_discovery_llm(),
                                 max_invariants=config.DISCOVERY_MAX_INVARIANTS)

    for p in result["proven"]:
        print(f"  [DISCOVERY] PROVEN       {p['invariant']}   [{p['verdict']}]")
    for b in result["broken"]:
        print(f"  [DISCOVERY] BROKEN       {b['invariant']}   violated by {b['violated_by']}")
    for i in result["inconclusive"]:
        print(f"  [DISCOVERY] INCONCLUSIVE {i['invariant']}   [{i['verdict']}]")
    if result["rejected"]:
        print(f"  [DISCOVERY] {len(result['rejected'])} proposal(s) rejected by "
              f"symbol/syntax validation (never reached the solver)")

    with open(config.REPORTS_FOLDER / f"{stem}_discovery.json", "w",
              encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    findings = []
    for idx, b in enumerate(result["broken"], 1):
        built = _discovery_finding(stem, b)
        findings.append(built)
        with open(config.FINDINGS_FOLDER / f"{stem}_invfinding_{idx}.json", "w",
                  encoding="utf-8") as fh:
            json.dump(built, fh, indent=2)
    print(f"  [DISCOVERY] {len(result['proven'])} proven | {len(result['broken'])} broken | "
          f"{len(result['inconclusive'])} inconclusive | {len(result['rejected'])} rejected")
    return findings


def run_pipeline(contract_folder: str = None) -> list:
    """Runs the full audit graph over a folder of .sol files and returns
    a list of FindingSchema dicts (one per verified finding)."""
    contract_folder = contract_folder or config.CONTRACTS_FOLDER
    if not contract_folder:
        raise SystemExit(
            "No contracts folder specified. Pass --contracts <folder> or set "
            "GODEL_CONTRACTS_FOLDER (audit fix: no more silent zero-finding runs)."
        )
    if not os.path.isdir(contract_folder):
        raise SystemExit(
            f"Contracts folder does not exist: '{contract_folder}'. "
            "Pass a valid --contracts <folder> or fix GODEL_CONTRACTS_FOLDER."
        )
    readme_path = os.path.join(contract_folder, "README.md")
    readme = open(readme_path, "r", encoding="utf-8").read() if os.path.exists(readme_path) else ""

    sol_files = collect_sol_files(contract_folder)
    if not sol_files:
        print(f"No .sol files found in {contract_folder}/")
        return []

    app = build_godel_graph()

    if not config.is_dry_run():
        warmup_rag()

    print("\n" + "=" * 50)
    print("=== STARTING GÖDEL MULTI-AGENT ORCHESTRATOR ===")
    print("=" * 50)

    results = []
    for sol_path in sol_files:
        stem = Path(sol_path).stem
        xml_str = parse_solidity_to_xml(sol_path)

        if not xml_str:
            print(f"  Skipping (parse failed): {sol_path}")
            continue

        xml_out = os.path.join(str(config.XML_OUTPUT_FOLDER), f"{stem}.xml")
        with open(xml_out, "w", encoding="utf-8") as f:
            f.write(xml_str)

        raw_solidity_code = open(sol_path, "r", encoding="utf-8").read()

        # Phase 1: static-analysis abstraction layer (non-fatal; deterministic).
        # Runs once per FILE (whole-contract CFG context), sliced per function
        # inside process_function. Skipped in dry-run to keep plumbing fast.
        static_analysis = None
        if not config.is_dry_run():
            static_analysis = abstract_contract(sol_path)
            if static_analysis:
                n_fns = len(static_analysis.get("functions", {}))
                n_det = len(static_analysis.get("detectors", []))
                print(f"  [ABSTRACTER] {stem}: {n_fns} function(s) abstracted, "
                      f"{n_det} High/Medium detector signal(s)")
            else:
                print(f"  [ABSTRACTER] {stem}: static analysis unavailable — continuing without it")

        env_setup = extract_element_text(xml_str, "environment_setup")
        interfaces = extract_element_text(xml_str, "interface")
        state_vars = extract_element_text(xml_str, "state_variables")
        functions = extract_functions_from_xml(xml_str)

        # Scope fan-out to the primary contract: flattened files inline
        # library/interface/base stubs that must not spawn audit graphs.
        functions, excluded = scope_functions_to_primary_contract(functions, stem)
        if excluded:
            shown = ", ".join(excluded[:12]) + ("..." if len(excluded) > 12 else "")
            print(f"      [SCOPE] primary contract only — excluded {len(excluded)} "
                  f"function(s) from inlined libraries/interfaces/bases: {shown}")

        # Optional targeted audit: GODEL_FUNCTIONS=name1,name2 restricts the
        # fan-out to the listed functions (case-insensitive), keeping
        # credit-sensitive runs surgical. Unknown names warn, never crash.
        fn_filter = os.environ.get("GODEL_FUNCTIONS", "").strip()
        if fn_filter:
            wanted = {n.strip().lower() for n in fn_filter.split(",") if n.strip()}
            selected = [f for f in functions if f["name"].lower() in wanted]
            matched = {f["name"].lower() for f in selected}
            missing = sorted(wanted - matched)
            if missing:
                print(f"      [TARGET] WARNING: not found in contract: {', '.join(missing)}")
            print(f"      [TARGET] GODEL_FUNCTIONS filter active — auditing "
                  f"{len(selected)}/{len(functions)} function(s): "
                  f"{', '.join(f['name'] for f in selected)}")
            functions = selected

        print(f"\nProcessing File: {sol_path} ({len(functions)} valid execution functions identified)")

        if config.SKIP_READONLY_FUNCTIONS:
            kept, skipped = [], []
            for func in functions:
                if is_read_only_function(static_analysis, func["name"]):
                    skipped.append(func["name"])
                else:
                    kept.append(func)
            if skipped:
                print(f"      [FAST PATH] skipped {len(skipped)} read-only function(s) "
                      f"(no state writes / no external calls): {', '.join(skipped)}")
            functions = kept

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=config.MAX_WORKERS)
        future_to_func = {
            executor.submit(process_function, func, raw_solidity_code, stem, readme,
                            env_setup, interfaces, state_vars, app, static_analysis): func["name"]
            for func in functions
        }
        batch_timeout = batch_timeout_for(len(functions))
        processed = set()
        try:
            for future in concurrent.futures.as_completed(future_to_func, timeout=batch_timeout):
                func_name = future_to_func[future]
                processed.add(id(future))
                try:
                    _collect_future_result(future, func_name, stem, results)
                except Exception as exc:
                    logger.error("[GRAPH ERROR] %s raised an exception: %s", func_name, exc)
                    traceback.print_exc()
                    # Ironclad rule: a raised graph must still surface in the
                    # report, or the function silently drops from the audit.
                    results.append(_error_finding(stem, func_name, exc))
        except concurrent.futures.TimeoutError:
            # Salvage pass 1: futures that finished between the last
            # as_completed yield and the timeout still hold valid results —
            # collect them instead of silently discarding (audit fix).
            for future, func_name in future_to_func.items():
                if id(future) in processed:
                    continue
                if future.done() and not future.cancelled():
                    try:
                        print(f"      [BATCH TIMEOUT SALVAGE] Collecting late-finished result for {func_name}")
                        _collect_future_result(future, func_name, stem, results)
                        processed.add(id(future))
                    except Exception as exc:
                        logger.error("[GRAPH ERROR] %s raised an exception during salvage: %s", func_name, exc)
                        results.append(_error_finding(stem, func_name, exc))
                        processed.add(id(future))

            # Salvage pass 2 (grace window): threads still alive past the
            # deadline are usually one LLM round from saving verified
            # findings. Declaring them dead immediately split-brained the
            # report — CI run 33307904841 printed SUMMARY with 2 findings
            # while the still-running repay graph went on to save its 2nd
            # confirmed finding to disk. Wait a bounded grace window and
            # collect whatever finishes inside it.
            remaining = [f for f in future_to_func
                         if id(f) not in processed and not f.done()]
            if remaining:
                names = ", ".join(future_to_func[f] for f in remaining)
                print(f"      [BATCH TIMEOUT GRACE] {len(remaining)} graph(s) still "
                      f"running ({names}) — waiting up to {config.BATCH_TIMEOUT_GRACE:.0f}s "
                      f"before declaring timeout")
                try:
                    for future in concurrent.futures.as_completed(
                            remaining, timeout=config.BATCH_TIMEOUT_GRACE):
                        func_name = future_to_func[future]
                        processed.add(id(future))
                        try:
                            print(f"      [BATCH TIMEOUT GRACE] Collecting result for {func_name}")
                            _collect_future_result(future, func_name, stem, results)
                        except Exception as exc:
                            logger.error("[GRAPH ERROR] %s raised an exception during grace salvage: %s", func_name, exc)
                            results.append(_error_finding(stem, func_name, exc))
                except concurrent.futures.TimeoutError:
                    pass

            # Anything still unfinished after the grace window gets a timeout
            # placeholder now; _drain_late_futures swaps in real results if
            # the thread finishes before process exit.
            for future, func_name in future_to_func.items():
                if id(future) in processed or future.cancelled():
                    continue
                if future.done():
                    processed.add(id(future))
                    try:
                        _collect_future_result(future, func_name, stem, results)
                    except Exception as exc:
                        logger.error("[GRAPH ERROR] %s raised an exception during salvage: %s", func_name, exc)
                        results.append(_error_finding(stem, func_name, exc))
                    continue
                logger.warning("[GRAPH TIMEOUT] %s exceeded the per-function timeout.", func_name)
                results.append(_timeout_finding(stem, func_name))
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        # Phase C (compositional): contract-wide invariant discovery. Runs
        # AFTER the per-function graphs so its findings merge into the same
        # results list and land in the audit summary. One fast LLM proposal
        # call + local Z3 sweep; non-fatal — a discovery failure must never
        # sink the per-function verdicts already collected.
        if config.RUN_DISCOVERY and static_analysis and not config.is_dry_run():
            try:
                results.extend(_run_discovery_phase(stem, static_analysis))
            except Exception as exc:
                logger.error("[DISCOVERY] phase failed for %s (non-fatal): %s", stem, exc)
                print(f"  [DISCOVERY] {stem}: phase failed — non-fatal "
                      f"({type(exc).__name__}: {str(exc)[:200]})")

        # Final drain: graphs that outlived even the grace window. Python
        # joins ThreadPoolExecutor threads at interpreter shutdown anyway, so
        # the process cannot exit until they finish — waiting here explicitly
        # costs no extra wall-clock and converts their zombie work into
        # collected results (SUMMARY stays in sync with what lands on disk).
        _drain_late_futures(future_to_func, processed, stem, results)

    print("\n" + "=" * 50 + "\n=== SYSTEM PIPELINE EXECUTION COMPLETE ===\n" + "=" * 50)
    return results


def _drain_late_futures(future_to_func: dict, processed: set, stem: str, results: list):
    """Collects graphs that outlived the batch timeout + grace window. Their
    threads keep the process alive regardless (Python joins executor threads
    at shutdown), so draining explicitly just turns that unavoidable wait
    into collected results. A real late result supersedes the timeout
    placeholder appended when the deadline fired — without this, SUMMARY
    undercounts the findings the same run saves to disk.

    The drain is capped at PER_FUNCTION_TIMEOUT: every inner operation (LLM
    call, Z3/forge subprocess, embed) already has its own timeout, so a
    healthy straggler finishes well inside the cap; a genuinely wedged
    thread must not hang the pipeline forever."""
    late = [f for f in future_to_func
            if id(f) not in processed and not f.cancelled()]
    if not late:
        return
    names = ", ".join(future_to_func[f] for f in late)
    cap = config.PER_FUNCTION_TIMEOUT
    print(f"      [LATE DRAIN] {len(late)} graph(s) outlived the grace window "
          f"({names}) — collecting before exit (cap {cap:.0f}s)")
    try:
        for future in concurrent.futures.as_completed(late, timeout=cap):
            func_name = future_to_func[future]
            processed.add(id(future))
            try:
                _collect_future_result(future, func_name, stem, results)
            except Exception as exc:
                logger.error("[GRAPH ERROR] %s raised an exception during late drain: %s", func_name, exc)
                results.append(_error_finding(stem, func_name, exc))
                continue
            results[:] = [r for r in results
                          if not (r.get("contract") == stem
                                  and r.get("function") == func_name
                                  and r.get("qc_status") == "timeout")]
    except concurrent.futures.TimeoutError:
        stuck = [future_to_func[f] for f in late if id(f) not in processed]
        logger.error("[LATE DRAIN] cap exceeded — abandoning: %s "
                     "(their timeout placeholders stand)", ", ".join(stuck))
        print(f"      [LATE DRAIN] WARNING: {', '.join(stuck)} did not finish "
              f"within the drain cap — timeout placeholders kept")


def _collect_future_result(future, func_name: str, stem: str, results: list):
    """Extracts a finished graph result and appends findings. Shared by the
    normal completion loop and the batch-timeout salvage path."""
    final_state = future.result()
    focus_func = final_state.get('current_focus_function', 'unknown')
    bugs_found = len(final_state.get('verified_bugs', []))

    rag_diag = final_state.get("rag_diagnostics") or {}
    rag_ps = rag_diag.get("precisions", {})
    p5 = rag_ps.get(5, {}).get("p_at_k")
    p3 = rag_ps.get(3, {}).get("p_at_k")
    p1 = rag_ps.get(1, {}).get("p_at_k")
    if p5 is not None:
        print(f"      [RAG] {focus_func}: P@1={p1} P@3={p3} P@5={p5} "
              f"n_retrieved={rag_diag.get('n_retrieved')} "
              f"elapsed={rag_diag.get('elapsed')}s")

    if config.is_dry_run():
        print(f"  [GRAPH OUTPUT] {focus_func}: dry-run plumbing OK (LLM nodes mocked)")
    elif bugs_found > 0:
        print(f"  [GRAPH OUTPUT] {bugs_found} verified vulnerabilities found & fixed in {focus_func}!")
        print(f"  [GRAPH OUTPUT] Terminal state: {_classify_terminal_state(final_state)}")
    else:
        verdict = _classify_terminal_state(final_state)
        is_genuine_safe = (
            ("(UNSAT" in verdict or verdict.startswith("verified mathematically safe"))
            and "vacuously" not in verdict
        )
        tag = "SAFE" if is_genuine_safe else "NOT SAFE / INCOMPLETE"
        print(f"  [GRAPH OUTPUT] {focus_func}: {verdict} [{tag}]")

    for bug in final_state.get("verified_bugs", []):
        results.append(build_finding(
            bug["finding"],
            final_state,
            bug.get("fix_code", ""),
            bug.get("poc_test_code", ""),
            bug.get("forge_output", ""),
            bug.get("qc_status", ""),
        ))

    if bugs_found == 0 and not config.is_dry_run():
        reason = _should_flag_incomplete(final_state)
        if reason:
            print(f"      [IRONCLAD] {focus_func}: surfacing incomplete-analysis artifact ({reason})")
            results.append(_incomplete_finding(stem, focus_func, reason))


def run_pipeline_code(contract_code: str, readme: str = "") -> list:
    """Runs the pipeline on raw Solidity code (MCP/chat entry point).
    Materializes the code into a temp folder, then delegates to run_pipeline."""
    with tempfile.TemporaryDirectory(prefix="godel_mcp_") as tmpdir:
        src_path = os.path.join(tmpdir, "contract.sol")
        with open(src_path, "w", encoding="utf-8") as f:
            f.write(contract_code)
        if readme:
            with open(os.path.join(tmpdir, "README.md"), "w", encoding="utf-8") as f:
                f.write(readme)
        return run_pipeline(tmpdir)


# ==========================================
# CLI ENTRY POINT
# ==========================================
def main():
    results = run_pipeline()
    print(f"\n=== SUMMARY: {len(results)} verified finding(s) ===")
    for r in results:
        print(f"  [{r.get('severity', 'unknown').upper()}] {r.get('contract')}::{r.get('function')} ({r.get('qc_status', 'unknown')})")
    return results


if __name__ == "__main__":
    main()
