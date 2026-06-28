import os
from dotenv import load_dotenv
from domain.arbiter import Arbiter
from langchain_openai import ChatOpenAI
from Infrastructure.postgres import retrieve
from domain.propertygenerator import PropertyGenerator
from domain.cegis import CEGIS
from domain.state import GraphState
from langchain_core.tools import tool
import subprocess
import tempfile

load_dotenv()

# @tool
def run_z3(z3_code: str) -> dict:
    """Executes Z3 Python code and returns the result."""
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
            if "Property holds" in output:
                status = "unsat"
            else:
                status = "sat"
            return {
                "status": status,
                "output": output,
                "error": None,
                "z3_code": z3_code
            }
        else:
            return {
                "status": "error",
                "output": None,
                "error": result.stderr,
                "z3_code": z3_code
            }
    finally:
        os.unlink(temp_path)

# 1. Load contract
with open("RugToken.sol", "r") as f:
    contract_code = f.read()

# 2. Initialize state
state: GraphState = {
    "user_intent_raw": "Verify owner cannot mint unlimited tokens or drain all funds",
    "user_contract": contract_code,
    "mode": "",
    "intent": "",
    "queries": [],
    "findings": [],
    "z3_code": "",
    "z3_result": None,
    "status": "running",
    "bug_report": None,
    "iterations": 0
}

# 3. Arbiter
llm_flash = ChatOpenAI(
    model="deepseek-v4-flash",
    openai_api_key=os.environ.get("DEEPSEEK_API_KEY"),
    openai_api_base="https://api.deepseek.com",
    extra_body={"thinking": {"type": "enabled", "budget_tokens": 16000}}
)

arbiter = Arbiter(agent=llm_flash)
resultsfromExpansion = arbiter.QueryArbiter(state["user_intent_raw"])
print("=== ARBITER OUTPUT ===")
print(resultsfromExpansion)

state["mode"] = resultsfromExpansion["mode"]
state["intent"] = resultsfromExpansion["intent"]
state["queries"] = resultsfromExpansion["queries"]

# 4. RAG + PropertyGenerator + CEGIS (z3 mode only)
if state["mode"] == "z3":

    # RAG
    resultsFromRAG = retrieve(state["queries"])
    state["findings"] = resultsFromRAG
    print("\n=== RAG OUTPUT ===")
    for r in resultsFromRAG:
        print(r["title_normalized"], "|", r["vuln_class"], "|", r["rerank_score"])

    # PropertyGenerator
    generator = PropertyGenerator(agent=llm_flash)
    generator.build_prompt(resultsfromExpansion, contract_code, resultsFromRAG)
    z3_code = generator.propertyGeneration()
    state["z3_code"] = z3_code
    print("\n=== GENERATED Z3 CODE ===")
    print(z3_code)

    # CEGIS
    llm_pro = ChatOpenAI(
        model="deepseek-v4-pro",
        openai_api_key=os.environ.get("DEEPSEEK_API_KEY"),
        openai_api_base="https://api.deepseek.com",
        extra_body={"thinking": {"type": "enabled", "budget_tokens": 16000}}
    ).bind_tools([run_z3])

    cegis = CEGIS(agent=llm_pro, run_z3_tool=run_z3)
    state = cegis.cegis_loop(state)

    print("\n=== FINAL STATUS ===")
    print("Status:", state["status"])
    print("Bug Report:", state["bug_report"])

elif state["mode"] == "standard":
    # conversational mode, skip RAG and Z3
    print("Standard mode — no formal verification needed")





# from typing import TypedDict, Optional


# class GraphState(TypedDict):
#     # Input
#     user_intent_raw: str
#     user_contract: str
    
#     # Arbiter output
#     mode: str
#     intent: str
#     queries: list[str]
    
#     # RAG output
#     findings: list[dict]
    
#     # PropertyGenerator output
#     z3_code: str
    
#     # CEGIS output
#     z3_result: Optional[dict]
#     status: str        # "running" | "verified" | "bug_found" | "needs_review"
#     bug_report: Optional[str]
#     iterations: int