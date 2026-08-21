import os
import re
import sys
import logging
import tempfile
import traceback
import concurrent.futures
from pathlib import Path

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.messages import AIMessage
from langgraph.graph import StateGraph, END

from piyoxml import parse_solidity_to_xml
from domain import config
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
from domain.schema import build_finding

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
    max_retries=3,
)

llm_pro = ChatOpenAI(
    model="deepseek-v4-pro",
    openai_api_key=os.environ.get("DEEPSEEK_API_KEY"),
    temperature=0.2,
    max_tokens=24000,
    openai_api_base="https://api.deepseek.com",
    extra_body={"thinking": {"type": "enabled", "budget_tokens": 12000}},
    timeout=120,
    max_retries=3,
)

inspector = Inspector(llm_pro, llm_pro)
generator = PropertyGenerator(agent=llm_flash)
property_verifier = PropertyVerifierAgent(agent_llm=llm_pro)
gatekeeper = FoundryGatekeeper(project_root=str(config.FOUNDRY_ROOT), verifier_agent=property_verifier)
fixer = FixerAgent(agent=llm_pro)
formatter = SubmissionFormatter()
cegis = CEGIS(agent=llm_pro, run_z3_tool=run_z3)


# ==========================================
# HELPER FUNCTIONS
# ==========================================
def extract_element_text(xml_string: str, tag_name: str) -> str:
    pattern = rf"<{tag_name}.*?>(.*?)</{tag_name}>"
    matches = re.findall(pattern, xml_string, re.DOTALL)
    cleaned = []
    for m in matches:
        c = m.replace("<![CDATA[", "").replace("]]>", "").strip()
        if c:
            cleaned.append(c)
    return "\n".join(cleaned)


def extract_functions_from_xml(xml_string: str) -> list:
    pattern = r'<function\s+name="([^"]+)"[^>]*>(.*?)</function>'
    matches = re.findall(pattern, xml_string, re.DOTALL)
    functions = []
    for name, body in matches:
        if "{" not in body:
            continue
        cleaned_body = body.replace("<![CDATA[", "").replace("]]>", "").strip()
        functions.append({"name": name, "body": cleaned_body})
    return functions


def collect_sol_files(folder: str) -> list:
    sol_files = []
    for root, _, files in os.walk(folder):
        for file in sorted(files):
            if file.endswith(".sol"):
                sol_files.append(os.path.join(root, file))
    return sol_files


def process_function(func, raw_solidity_code, stem, readme, env_setup, interfaces, state_vars, app):
    print(f"  -> Spawning Graph Thread for [{func['name']}]...")

    injection_packet = f"""<analysis_packet>
    <environment_wiring>
        <setup>{env_setup}</setup>
        <interfaces>{interfaces}</interfaces>
        <global_storage_slots>{state_vars}</global_storage_slots>
    </environment_wiring>
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
        "slither_result": None,
        "bug_report": None,
        "iterations": 0,
        "supervisor_runs": 0,
        "executor_runs": 0,
        "poc_test_code": "",
        "forge_output": "",
        "qc_status": "",
        "isolated_xml_packet": injection_packet,
    }

    return app.invoke(initial_state)


# ==========================================
# NODE WRAPPERS
# ==========================================
def node_supervisor(state: GraphState): return supervisor_node(state, llm_pro)


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
    if state.get("supervisor_critique"):
        return "supervisor"
    return "executor"


def route_after_executor(state: GraphState) -> str:
    res = state.get("z3_result", {})
    status = res.get("status")
    if status == "error":
        if state.get("executor_runs", 0) >= config.EXECUTOR_MAX_ITERATIONS:
            return END
        return "specifier"
    elif status == "sat":
        return "gatekeeper"
    return END


def route_after_gatekeeper(state: GraphState) -> str:
    if state.get("verified_bugs"):
        return "fixer"
    return END


def build_godel_graph():
    workflow = StateGraph(GraphState)

    workflow.add_node("supervisor", node_supervisor)
    workflow.add_node("bug_hunter", node_bug_hunter)
    workflow.add_node("specifier", node_specifier)
    workflow.add_node("executor", node_executor)
    workflow.add_node("gatekeeper", node_gatekeeper)
    workflow.add_node("fixer", node_fixer)

    workflow.add_conditional_edges("bug_hunter", route_after_hunter)

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
        {"fixer": "fixer", END: END},
    )

    workflow.add_edge("fixer", END)
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


def run_pipeline(contract_folder: str = None) -> list:
    """Runs the full audit graph over a folder of .sol files and returns
    a list of FindingSchema dicts (one per verified finding)."""
    contract_folder = contract_folder or config.CONTRACTS_FOLDER
    readme_path = os.path.join(contract_folder, "README.md")
    readme = open(readme_path, "r", encoding="utf-8").read() if os.path.exists(readme_path) else ""

    sol_files = collect_sol_files(contract_folder)
    if not sol_files:
        print(f"No .sol files found in {contract_folder}/")
        return []

    app = build_godel_graph()

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

        env_setup = extract_element_text(xml_str, "environment_setup")
        interfaces = extract_element_text(xml_str, "interface")
        state_vars = extract_element_text(xml_str, "state_variables")
        functions = extract_functions_from_xml(xml_str)

        print(f"\nProcessing File: {sol_path} ({len(functions)} valid execution functions identified)")

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=config.MAX_WORKERS)
        future_to_func = {
            executor.submit(process_function, func, raw_solidity_code, stem, readme,
                            env_setup, interfaces, state_vars, app): func["name"]
            for func in functions
        }
        batch_timeout = config.PER_FUNCTION_TIMEOUT * max(1, len(functions))
        try:
            for future in concurrent.futures.as_completed(future_to_func, timeout=batch_timeout):
                func_name = future_to_func[future]
                try:
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

                    if bugs_found > 0:
                        print(f"  [GRAPH OUTPUT] {bugs_found} verified vulnerabilities found & fixed in {focus_func}!")
                    else:
                        print(f"  [GRAPH OUTPUT] {focus_func} verified mathematically safe.")

                    for bug in final_state.get("verified_bugs", []):
                        results.append(build_finding(
                            bug["finding"],
                            final_state,
                            bug.get("fix_code", ""),
                            bug.get("poc_test_code", ""),
                            bug.get("forge_output", ""),
                            bug.get("qc_status", ""),
                        ))
                except Exception as exc:
                    logger.error("[GRAPH ERROR] %s raised an exception: %s", func_name, exc)
                    traceback.print_exc()
        except concurrent.futures.TimeoutError:
            for future, func_name in future_to_func.items():
                if not future.done():
                    logger.warning("[GRAPH TIMEOUT] %s exceeded the per-function timeout.", func_name)
                    results.append(_timeout_finding(stem, func_name))
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

    print("\n" + "=" * 50 + "\n=== SYSTEM PIPELINE EXECUTION COMPLETE ===\n" + "=" * 50)
    return results


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
