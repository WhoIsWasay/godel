import os
import json
from dotenv import load_dotenv
from domain.arbiter import Arbiter
from langchain_openai import ChatOpenAI
from Infrastructure.postgres import retrieve
from domain.propertygenerator import PropertyGenerator
from domain.cegis import CEGIS
from domain.state import GraphState
from domain.slither_runner import run_slither
import subprocess
import tempfile

import sys
sys.stdout.reconfigure(encoding='utf-8')

load_dotenv()

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

    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "output": None,
            "error": "Z3 timeout — model too complex, simplify bounds",
            "z3_code": z3_code
        }

    except Exception as e:
        return {
            "status": "error",
            "output": None,
            "error": str(e),
            "z3_code": z3_code
        }

    finally:
        os.unlink(temp_path)


# 1. Load contract
contract_path = "LendingPool.sol"
with open(contract_path, "r") as f:
    contract_code = f.read()

# 2. Initialize state
state: GraphState = {
    "user_intent_raw": "Verify that interest rate cannot be set by unauthorized users, liquidation cannot be manipulated via oracle price, and share ratio cannot be inflated by first depositor",
    "user_contract": contract_code,
    "mode": "",
    "intent": "",
    "queries": [],
    "findings": [],
    "z3_code": "",
    "z3_result": None,
    "slither_result": None,
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

llm_pro = ChatOpenAI(
    model="deepseek-v4-pro",
    openai_api_key=os.environ.get("DEEPSEEK_API_KEY"),
    openai_api_base="https://api.deepseek.com",
    extra_body={"thinking": {"type": "enabled", "budget_tokens": 16000}}
)

if state["mode"] == "z3":

    resultsFromRAG = retrieve(state["queries"])
    state["findings"] = resultsFromRAG
    print("\n=== RAG OUTPUT ===")
    for r in resultsFromRAG:
        print(r["title_normalized"], "|", r["vuln_class"], "|", r["rerank_score"])

    generator = PropertyGenerator(agent=llm_flash)
    generator.build_prompt(resultsfromExpansion, contract_code, resultsFromRAG)
    z3_code = generator.propertyGeneration()
    state["z3_code"] = z3_code
    print("\n=== GENERATED Z3 CODE ===")
    print(z3_code)

    cegis = CEGIS(agent=llm_pro, run_z3_tool=run_z3)
    state = cegis.cegis_loop(state)

elif state["mode"] == "slither":

    print("\n=== RUNNING SLITHER ===")
    slither_result = run_slither(contract_path)
    state["slither_result"] = slither_result
    print(f"Findings: {slither_result['findings_count']}")

    cegis = CEGIS(agent=llm_pro, run_z3_tool=run_z3)
    state = cegis.cegis_loop(state)

elif state["mode"] == "both":

    print("\n=== RUNNING SLITHER ===")
    slither_result = run_slither(contract_path)
    state["slither_result"] = slither_result
    print(f"Slither findings: {slither_result['findings_count']}")

    resultsFromRAG = retrieve(state["queries"])
    state["findings"] = resultsFromRAG
    print("\n=== RAG OUTPUT ===")
    for r in resultsFromRAG:
        print(r["title_normalized"], "|", r["vuln_class"], "|", r["rerank_score"])

    generator = PropertyGenerator(agent=llm_flash)
    generator.build_prompt(resultsfromExpansion, contract_code, resultsFromRAG)
    z3_code = generator.propertyGeneration()
    state["z3_code"] = z3_code
    print("\n=== GENERATED Z3 CODE ===")
    print(z3_code)

    cegis = CEGIS(agent=llm_pro, run_z3_tool=run_z3)
    state = cegis.cegis_loop(state)

elif state["mode"] == "standard":
    print("Standard mode — no formal verification needed")

if state["mode"] != "standard":
    print("\n=== FINAL STATUS ===")
    print("Status:", state["status"])
    print("Bug Report:", state["bug_report"])