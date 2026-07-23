import os
import re
import json
import subprocess
import tempfile
import sys
from pathlib import Path
from datetime import date
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END

import concurrent.futures
import traceback # Put this at the very top of orchestrator.py
# Existing Domain Tools
from domain.inspector import Inspector
from domain.arbiter import Arbiter
from domain.propertygenerator import PropertyGenerator
from domain.cegis import CEGIS
from domain.gatekeeper import FoundryGatekeeper
from domain.fixer import FixerAgent
from domain.formatter import SubmissionFormatter
from domain.verifier import PropertyVerifierAgent

# New Graph State and Node Functions
from domain.state import GraphState
from domain.graph_nodes import (
    supervisor_node, 
    bug_hunter_node, 
    specifier_node, 
    executor_node, 
    gatekeeper_node, 
    fixer_node
)

# External Parsers
from piyoxml import parse_solidity_to_xml

sys.stdout.reconfigure(encoding='utf-8')
load_dotenv()

# ==========================================
# CONFIGURATION
# ==========================================
CONTRACTS_FOLDER   = "FolderName"
XML_OUTPUT_FOLDER  = "output/xml"
FINDINGS_FOLDER    = "output/findings"
REPORTS_FOLDER     = "output/reports"
PROOFS_FOLDER      = "output/proofs"
FIXES_FOLDER       = "output/fixes"
SUBMISSIONS_FOLDER = "output/submissions"

os.makedirs(XML_OUTPUT_FOLDER, exist_ok=True)
os.makedirs(FINDINGS_FOLDER,   exist_ok=True)
os.makedirs(REPORTS_FOLDER,    exist_ok=True)
os.makedirs(PROOFS_FOLDER,     exist_ok=True)
os.makedirs(FIXES_FOLDER,      exist_ok=True)
os.makedirs(SUBMISSIONS_FOLDER, exist_ok=True)

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
        "isolated_xml_packet": injection_packet 
    }

    return app.invoke(initial_state)

# ==========================================
# HELPER FUNCTIONS & RUNNERS (Must be defined first)
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

def run_z3(z3_code: str) -> dict:
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(z3_code)
        temp_path = f.name

    try:
        result = subprocess.run(
            ["python", temp_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            output = result.stdout.strip()
            status = "unsat" if "Property holds" in output else "sat"
            return {"status": status, "output": output, "error": None, "z3_code": z3_code}
        else:
            return {"status": "error", "output": None, "error": result.stderr, "z3_code": z3_code}
    except subprocess.TimeoutExpired:
        return {"status": "error", "output": None, "error": "Z3 timeout", "z3_code": z3_code}
    except Exception as e:
        return {"status": "error", "output": None, "error": str(e), "z3_code": z3_code}
    finally:
        os.unlink(temp_path)

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

# Core Tooling initialized after the LLMs and helper functions
inspector = Inspector(llm_pro, llm_pro) # <-- UPGRADED TO PRO
generator = PropertyGenerator(agent=llm_flash)
property_verifier = PropertyVerifierAgent(agent_llm=llm_pro)
gatekeeper = FoundryGatekeeper(project_root=".", verifier_agent=property_verifier)
fixer = FixerAgent(agent=llm_pro)
formatter = SubmissionFormatter()
cegis = CEGIS(agent=llm_pro, run_z3_tool=run_z3)  # run_z3 is successfully referenced here

# ==========================================
# NODE WRAPPERS
# ==========================================
def node_supervisor(state: GraphState): return supervisor_node(state, llm_pro)
def node_bug_hunter(state: GraphState): return bug_hunter_node(state, inspector)
def node_specifier(state: GraphState): return specifier_node(state, generator)
def node_executor(state: GraphState): return executor_node(state, cegis)
def node_gatekeeper(state: GraphState): return gatekeeper_node(state, gatekeeper)
def node_fixer(state: GraphState): return fixer_node(state, fixer, formatter)


# ==========================================
# GRAPH ROUTING LOGIC (Escalation Pipeline)
# ==========================================
def route_after_hunter(state: GraphState) -> str:
    """If the hunter finds nothing, exit immediately."""
    if not state.get("findings"):
        # Add this print statement so we know exactly when the Hunter bails out
        print(f"      [BUG HUNTER] No vulnerabilities detected in {state.get('current_focus_function')}. Exiting early.")
        return END
    return "supervisor"
def route_after_supervisor(state: GraphState) -> str:
    """If the supervisor approves, go to specifier. If rejected, retry up to limit."""
    critique = state.get("supervisor_critique")
    
    if critique:
        if state.get("iterations", 0) >= 3:
            print(f"      [🚨 GRAPH ABORT] Hunter loop limit reached for {state.get('current_focus_function')}.")
            # ADD THIS LINE to see exactly what the AI is arguing about
            print(f"      [🕵️‍♂️ SUPERVISOR REJECTION REASON]: {critique}") 
            return END
        return "bug_hunter"
    return "specifier"

def route_after_specifier(state: GraphState) -> str:
    """If the specifier flags a hallucination, escalate to Supervisor. Otherwise, execute."""
    if state.get("supervisor_critique"):
        return "supervisor" # Escalate up
    return "executor" # Proceed forward

def route_after_executor(state: GraphState) -> str:
    """Direct CEGIS loop handles Z3 code errors without waking up the supervisor."""
    res = state.get("z3_result", {})
    status = res.get("status")
    
    if status == "error":
        if state.get("iterations", 0) >= 4:
            return END
        return "specifier" # Local loop back to fix Z3 syntax
    elif status == "sat":
        return "gatekeeper" # Math holds a counterexample, verify in EVM
    return END # UNSAT (Safe), exit instantly

def route_after_gatekeeper(state: GraphState) -> str:
    """Route to fixer only if the bug is fully confirmed in dynamic execution."""
    if state.get("verified_bugs"):
        return "fixer"
    return END


# ==========================================
# COMPILE THE DECOUPLED GRAPH
# ==========================================
def build_godel_graph():
    workflow = StateGraph(GraphState)

    # 1. Add Nodes
    workflow.add_node("supervisor", node_supervisor)
    workflow.add_node("bug_hunter", node_bug_hunter)
    workflow.add_node("specifier", node_specifier)
    workflow.add_node("executor", node_executor)
    workflow.add_node("gatekeeper", node_gatekeeper)
    workflow.add_node("fixer", node_fixer)

    # 2. Add Conditional Routing (The Escalation Factory)
    
    # Bug Hunter checks code. If safe -> END. If suspicious -> Supervisor.
    workflow.add_conditional_edges("bug_hunter", route_after_hunter)
    
    # Supervisor evaluates. Routes to Specifier, or kicks back to Hunter.
    workflow.add_conditional_edges(
        "supervisor", 
        route_after_supervisor,
        {
            "bug_hunter": "bug_hunter",
            "specifier": "specifier",
            END: END
        }
    )
    
    # Specifier writes Z3. If impossible math -> Supervisor. Else -> Executor.
    workflow.add_conditional_edges(
        "specifier", 
        route_after_specifier,
        {"supervisor": "supervisor", "executor": "executor"}
    )
    
    # Executor runs Z3. Error -> Specifier. SAT -> Gatekeeper. UNSAT -> END.
    workflow.add_conditional_edges(
        "executor", 
        route_after_executor,
        {"specifier": "specifier", "gatekeeper": "gatekeeper", END: END}
    )
    
    # Gatekeeper tests EVM. Confirmed -> Fixer. False Positive -> END.
    workflow.add_conditional_edges(
        "gatekeeper", 
        route_after_gatekeeper,
        {"fixer": "fixer", END: END}
    )
    
    # Fixer is the end of the line.
    workflow.add_edge("fixer", END)

    # 3. Set Entry Point
    workflow.set_entry_point("bug_hunter") # Start with the cheap Flash hunter directly

    return workflow.compile()


# ==========================================
# MAIN EXECUTION
# ==========================================
def main():
    readme_path = os.path.join(CONTRACTS_FOLDER, "README.md")
    readme = open(readme_path, "r", encoding="utf-8").read() if os.path.exists(readme_path) else ""

    sol_files = collect_sol_files(CONTRACTS_FOLDER)
    if not sol_files:
        print(f"No .sol files found in {CONTRACTS_FOLDER}/")
        return

    app = build_godel_graph()
    
    print("\n" + "="*50)
    print("=== STARTING GÖDEL MULTI-AGENT ORCHESTRATOR ===")
    print("="*50)
    
    for sol_path in sol_files:
        stem = Path(sol_path).stem
        xml_str = parse_solidity_to_xml(sol_path)

        if not xml_str:
            print(f"  Skipping (parse failed): {sol_path}")
            continue

        xml_out = os.path.join(XML_OUTPUT_FOLDER, f"{stem}.xml")
        with open(xml_out, "w", encoding="utf-8") as f:
            f.write(xml_str)

        raw_solidity_code = open(sol_path, "r", encoding="utf-8").read()

        env_setup = extract_element_text(xml_str, "environment_setup")
        interfaces = extract_element_text(xml_str, "interface")
        state_vars = extract_element_text(xml_str, "state_variables")
        functions = extract_functions_from_xml(xml_str)

        print(f"\nProcessing File: {sol_path} ({len(functions)} valid execution functions identified)")
        
        # Kept max_workers at 2 to prevent API limits and hardware crashing
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(process_function, func, raw_solidity_code, stem, readme, env_setup, interfaces, state_vars, app)
                for func in functions
            ]
    
            for future in concurrent.futures.as_completed(futures):
                try:
                    final_state = future.result()
                    focus_func = final_state.get('current_focus_function', 'unknown')
                    bugs_found = len(final_state.get('verified_bugs', []))
            
                    if bugs_found > 0:
                        print(f"  🚨 [GRAPH OUTPUT] {bugs_found} verified vulnerabilities found & fixed in {focus_func}!")
                    else:
                        print(f"  🛡️ [GRAPH OUTPUT] {focus_func} verified mathematically safe.")
                except Exception as exc:
                    print(f"  ❌ [GRAPH ERROR] Execution generated an exception: {exc}")
                    traceback.print_exc()
    print("\n" + "="*50 + "\n=== SYSTEM PIPELINE EXECUTION COMPLETE ===\n" + "="*50)

if __name__ == "__main__":
    main()