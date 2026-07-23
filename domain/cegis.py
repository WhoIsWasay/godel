import json
from langchain_core.messages import SystemMessage, HumanMessage
from domain.state import GraphState
import os

class CEGIS:
    with open("prompts/cegis_prompt.txt", "r") as f:
        SYSTEM_PROMPT = f.read()

    def __init__(self, agent, run_z3_tool):
        self.agent = agent
        self.run_z3 = run_z3_tool

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
CONTRACTS_FOLDER   = "lendingPool"
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

# ==========================================
# LLM CLIENTS & AGENTS
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
    temperature=0.0,
    max_tokens=4096,
    openai_api_base="https://api.deepseek.com",
    extra_body={"thinking": {"type": "enabled", "budget_tokens": 16000}},
    timeout=120,
    max_retries=3,
)

# Initialize Core Tooling
inspector = Inspector(llm_flash, llm_flash)
generator = PropertyGenerator(agent=llm_flash)
property_verifier = PropertyVerifierAgent(agent_llm=llm_pro)
gatekeeper = FoundryGatekeeper(project_root=".", verifier_agent=property_verifier)
fixer = FixerAgent(agent=llm_pro)
formatter = SubmissionFormatter()

# ==========================================
# EXTRACTION & FILTERING HELPERS
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

# ==========================================
# Z3 RUNNER
# ==========================================
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

cegis = CEGIS(agent=llm_pro, run_z3_tool=run_z3)

# ==========================================
# NODE WRAPPERS
# ==========================================
def node_supervisor(state: GraphState): return supervisor_node(state, llm_pro)
def node_bug_hunter(state: GraphState): return bug_hunter_node(state, inspector)
def node_specifier(state: GraphState): return specifier_node(state, generator)
def node_executor(state: GraphState): return executor_node(state, cegis)
def node_gatekeeper(state: GraphState): return gatekeeper_node(state, gatekeeper)
def node_fixer(state: GraphState): return fixer_node(state, fixer, formatter)

def route_from_supervisor(state: GraphState) -> str:
    """Reads the Supervisor's decision and routes the graph accordingly."""
    destination = state.get("next_agent", "FINISH")
    if destination == "FINISH":
        return END
    return destination

# ==========================================
# COMPILE THE GRAPH
# ==========================================
def build_godel_graph():
    workflow = StateGraph(GraphState)

    workflow.add_node("supervisor", node_supervisor)
    workflow.add_node("bug_hunter", node_bug_hunter)
    workflow.add_node("specifier", node_specifier)
    workflow.add_node("executor", node_executor)
    workflow.add_node("gatekeeper", node_gatekeeper)
    workflow.add_node("fixer", node_fixer)

    workflow.add_edge("bug_hunter", "supervisor")
    workflow.add_edge("specifier", "supervisor")
    workflow.add_edge("executor", "supervisor")
    workflow.add_edge("gatekeeper", "supervisor")
    workflow.add_edge("fixer", "supervisor") 

    workflow.add_conditional_edges(
        "supervisor",
        route_from_supervisor,
        {
            "bug_hunter": "bug_hunter",
            "specifier": "specifier",
            "executor": "executor",
            "gatekeeper": "gatekeeper",
            "fixer": "fixer",
            END: END
        }
    )

    workflow.set_entry_point("supervisor")
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

        for func in functions:
            print(f"\n  -> Routing sandboxed function [{func['name']}] to Supervisor Graph...")
            
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

            final_state = app.invoke(initial_state)
            
            bugs_found = len(final_state.get('verified_bugs', []))
            if bugs_found > 0:
                print(f"  🚨 [GRAPH OUTPUT] {bugs_found} verified vulnerabilities found & fixed in {func['name']}!")
            else:
                print(f"  🛡️ [GRAPH OUTPUT] {func['name']} verified mathematically safe.")

    print("\n" + "="*50 + "\n=== SYSTEM PIPELINE EXECUTION COMPLETE ===\n" + "="*50)

if __name__ == "__main__":
    main()