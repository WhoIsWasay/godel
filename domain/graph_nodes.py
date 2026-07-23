# domain/graph_nodes.py

import os
import json
import re
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from domain.state import GraphState
from domain.inspector import Inspector
from domain.propertygenerator import PropertyGenerator
from domain.cegis import CEGIS
from domain.gatekeeper import FoundryGatekeeper
from domain.fixer import FixerAgent
from domain.formatter import SubmissionFormatter


def supervisor_node(state: GraphState, llm_pro):
    """The brain of the graph. Evaluates findings to filter hallucinations early."""
    
    with open("prompts/supervisor_prompt.txt", "r", encoding="utf-8") as f:
        supervisor_prompt = f.read()

    # FIX: Inject the actual contract code so the Supervisor isn't blind!
    state_summary = f"""
    TARGET FUNCTION UNDER ANALYSIS: {state.get('current_focus_function')}
    
    PROPOSED FINDINGS: 
    {json.dumps(state.get('findings', []), indent=2)}
    
    === TARGET CONTRACT CODE ===
    {state.get('user_contract', '')}
    """

    messages = [
        SystemMessage(content=supervisor_prompt),
        HumanMessage(content=f"Review the following proposed findings against the contract code:\n{state_summary}")
    ]

    response = llm_pro.invoke(messages)
    raw_content = response.content.strip()
    
    # Clean out any leaked <think> blocks
    raw_content = re.sub(r'<think>.*?</think>', '', raw_content, flags=re.DOTALL).strip()
    
    if "```json" in raw_content:
        raw_content = raw_content.split("```json")[1].split("```")[0].strip()
    elif "```" in raw_content:
        raw_content = raw_content.split("```")[1].split("```")[0].strip()
        
    try:
        # strict=False prevents crashes from unescaped newlines
        decision = json.loads(raw_content, strict=False)
        
        # Defend against LLM hallucinating an array instead of an object
        if isinstance(decision, list):
            decision = decision[0] if len(decision) > 0 else {}
            
        status = decision.get("status", "APPROVED").upper()
        
        return {
            "supervisor_critique": decision.get("supervisor_critique") if status == "REJECTED" else None,
            "messages": [AIMessage(content=f"[SUPERVISOR]: {decision.get('thought_process', 'Evaluation complete.')}")]
        }
    except json.JSONDecodeError as e:
        print(f"      [SUPERVISOR JSON ERROR] {e}. Forcing rejection to trigger heal.")
        return {
            "supervisor_critique": "Failed to parse routing JSON. You must output a valid JSON object.",
            "messages": [AIMessage(content="[SUPERVISOR ERROR]: Critical JSON structural parsing failure.")]
        }

# def supervisor_node(state: GraphState, llm_pro):
#     """The brain of the graph. Evaluates findings to filter hallucinations early."""
    
#     with open("prompts/supervisor_prompt.txt", "r", encoding="utf-8") as f:
#         supervisor_prompt = f.read()

#     state_summary = f"""
#     TARGET FUNCTION UNDER ANALYSIS: {state.get('current_focus_function')}
#     PROPOSED FINDINGS: {json.dumps(state.get('findings', []), indent=2)}
#     """

#     messages = [
#         SystemMessage(content=supervisor_prompt),
#         HumanMessage(content=f"Review the following proposed findings against the contract code:\n{state_summary}")
#     ]

#     response = llm_pro.invoke(messages)
#     raw_content = response.content.strip()
    
#     # Clean out any leaked <think> blocks
#     raw_content = re.sub(r'<think>.*?</think>', '', raw_content, flags=re.DOTALL).strip()
    
#     if "```json" in raw_content:
#         raw_content = raw_content.split("```json")[1].split("```")[0].strip()
#     elif "```" in raw_content:
#         raw_content = raw_content.split("```")[1].split("```")[0].strip()
        
#     try:
#         # strict=False prevents crashes from unescaped newlines
#         decision = json.loads(raw_content, strict=False)
        
#         # Defend against LLM hallucinating an array instead of an object
#         if isinstance(decision, list):
#             decision = decision[0] if len(decision) > 0 else {}
            
#         status = decision.get("status", "APPROVED").upper()
        
#         return {
#             "supervisor_critique": decision.get("supervisor_critique") if status == "REJECTED" else None,
#             "messages": [AIMessage(content=f"[SUPERVISOR]: {decision.get('thought_process', 'Evaluation complete.')}")]
#         }
#     except json.JSONDecodeError as e:
#         print(f"      [SUPERVISOR JSON ERROR] {e}. Forcing rejection to trigger heal.")
#         return {
#             "supervisor_critique": "Failed to parse routing JSON. You must output a valid JSON object.",
#             "messages": [AIMessage(content="[SUPERVISOR ERROR]: Critical JSON structural parsing failure.")]
#         }

def bug_hunter_node(state: GraphState, inspector: Inspector):
    """Invokes the Isolator to find bugs, with robust JSON defense and strict function scoping."""
    
    xml_packet = state.get("isolated_xml_packet", "")
    full_code = state.get("user_contract", "")
    readme = state.get("readme_specs", "")
    critique = state.get("supervisor_critique")
    focus_func = state.get("current_focus_function")
    
    # Inject full contract reference, but STRICTLY bound the AI to the focus function
    input_text = f"""[CRITICAL INSTRUCTION]
You are actively auditing the function named: `{focus_func}`. 
You MUST strictly evaluate this specific function. Do NOT report vulnerabilities found in other parts of the contract. The FULL CONTRACT REFERENCE is provided ONLY so you can cross-reference state variables and view/pure helpers.

=== SYSTEM README ===
{readme}

=== TARGET ISOLATION PACKET ===
{xml_packet}

=== FULL CONTRACT REFERENCE (For internal helper calls) ===
{full_code}"""

    if critique:
        input_text += f"\n\n[SUPERVISOR CRITIQUE]: {critique}\nFix your previous analysis based on this feedback."

    raw_response = inspector._invoke(inspector.isolator_agent, inspector.isolator_prompt, input_text)
    
    # --- ROBUST JSON EXTRACTION ---
    findings = []
    clean_response = re.sub(r'<think>.*?</think>', '', raw_response, flags=re.DOTALL).strip()
    
    try:
        if "```json" in clean_response:
            clean_response = clean_response.split("```json")[1].split("```")[0].strip()
        elif "```" in clean_response:
            clean_response = clean_response.split("```")[1].split("```")[0].strip()
        
        # strict=False fixes the "Invalid control character" error natively
        parsed_data = json.loads(clean_response, strict=False)
        
        if isinstance(parsed_data, dict):
            findings = parsed_data.get("findings", [])
        elif isinstance(parsed_data, list):
            findings = parsed_data
            
    except json.JSONDecodeError as e:
        print(f"      [BUG HUNTER WARNING] JSON Parse Error: {e}. Falling back to Inspector extractor...")
        try:
            # Fallback to the original external extractor if all else fails
            parsed_data = inspector.extract_json(raw_response)
            findings = parsed_data.get("findings", [])
        except Exception:
            findings = []
            
    if not isinstance(findings, list):
        findings = []
        
    if not findings:
        print(f"      [BUG HUNTER] No vulnerabilities detected in {state.get('current_focus_function')}. Exiting early.")
        
    return {
        "findings": findings,
        "messages": [AIMessage(content=f"[BUG HUNTER]: Proposed {len(findings)} findings.")]
    }

def specifier_node(state: GraphState, generator: PropertyGenerator):
    """Translates the finding into a Z3 property."""
    
    finding = state["findings"][0] if state.get("findings") else {}
    
    generator.build_prompt(
        {"intent": finding.get("intent", ""), "queries": []}, 
        state["user_contract"], 
        []
    )
    
    z3_code_raw = generator.propertyGeneration()
    
    if "[SUPERVISOR_ALERT]" in z3_code_raw:
        return {
            "supervisor_critique": z3_code_raw,
            "z3_code": "",
            "messages": [AIMessage(content=z3_code_raw)]
        }
    else:
        return {
            "z3_code": z3_code_raw,
            "messages": [AIMessage(content="[SPECIFIER]: Z3 Property Generated.")]
        }

def executor_node(state: GraphState, cegis_tool: CEGIS):
    """Executes the generated Z3 property."""
    
    z3_code = state.get("z3_code", "")
    if not z3_code:
        return {
            "supervisor_critique": "No Z3 code was provided to the executor.",
            "messages": [AIMessage(content="[EXECUTOR]: Failed. Missing Z3 code.")]
        }

    print(f"      [EXECUTOR] Running symbolic execution (Iteration {state.get('iterations', 0)})...")
    result = cegis_tool.run_z3(z3_code)
    
    updates = {
        "z3_result": result,
        "iterations": state.get("iterations", 0) + 1
    }
    
    if result["status"] == "sat":
        updates["bug_report"] = f"[Z3] Counterexample found:\n{result['output']}"
        updates["messages"] = [AIMessage(content="[EXECUTOR]: SAT. Counterexample found. Passing to Gatekeeper.")]
    elif result["status"] == "unsat":
        updates["messages"] = [AIMessage(content="[EXECUTOR]: UNSAT. Property holds safely.")]
    else:
        updates["supervisor_critique"] = f"Z3 Syntax/Execution Error:\n{result['error']}"
        updates["messages"] = [AIMessage(content="[EXECUTOR]: ERROR during execution. Needs refinement.")]
        
    return updates



def gatekeeper_node(state: GraphState, gatekeeper: FoundryGatekeeper):
    """Verifies EVM exploitability."""
    
    finding = state["findings"][0] if state.get("findings") else {}
    if not finding:
        return {"messages": [AIMessage(content="[GATEKEEPER]: No finding to verify.")]}
        
    # =====================================================================
    # --- AUTOMATED ENTERPRISE FIX: MATERIALIZE FILE FOR FOUNDRY ---
    import os
    import re
    
    # 1. Extract the REAL contract name from the source code (e.g., "SubscriptionBillingManager")
    # This prevents crashes if the original file was generically named "contract.sol"
    match = re.search(r'contract\s+([A-Za-z0-9_]+)', state["user_contract"])
    real_contract_name = match.group(1) if match else state['contract_name']
    real_filename = f"{real_contract_name}.sol"
    
    # 2. Ensure the src/ directory exists
    os.makedirs("src", exist_ok=True)
    
    # 3. Write the exact code into the src/ folder so Forge can always find it
    target_src_file = os.path.join("src", real_filename)
    try:
        with open(target_src_file, "w", encoding="utf-8") as f:
            f.write(state["user_contract"])
    except Exception as e:
        print(f"      [GATEKEEPER WARNING] Failed to materialize source file: {e}")
    # =====================================================================

    print(f"      [GATEKEEPER] Generating native EVM test suite for {finding.get('target_function')}...")
    
    # Pass the real filename we just created to the Verifier agent
    test_suite = gatekeeper.verifier_agent.generate_test_suite(
        finding, state, state["user_contract"], real_filename
    )
    
    qc_status = gatekeeper.execute_qc_validation(test_suite, debug_tag=f"{real_contract_name}_verify")
    
    if qc_status == "confirmed":
        new_bug = {
            "finding": finding,
            "z3_result": state.get("z3_result"),
            "bug_report": state.get("bug_report")
        }
        current_bugs = state.get("verified_bugs", [])
        return {
            "verified_bugs": current_bugs + [new_bug],
            "messages": [AIMessage(content="[GATEKEEPER]: Bug CONFIRMED in EVM execution.")]
        }
    elif qc_status == "property_held":
        return {
            "findings": [],
            "messages": [AIMessage(content="[GATEKEEPER]: FALSE POSITIVE. Property held during EVM execution. Dropping finding.")]
        }
    else:
        new_bug = {
            "finding": finding,
            "z3_result": state.get("z3_result"),
            "bug_report": state.get("bug_report", "") + f"\n\n[QC CRITICAL WARNING] Gatekeeper failed to execute native EVM tests ({qc_status}). Z3 proved this bug, but dynamic verification could not compile/run. MANUAL REVIEW REQUIRED."
        }
        current_bugs = state.get("verified_bugs", [])
        return {
            "verified_bugs": current_bugs + [new_bug],
            "messages": [AIMessage(content=f"[GATEKEEPER]: Execution failed ({qc_status}). Pushing Z3-proven bug to manual review.")]
        }

# def gatekeeper_node(state: GraphState, gatekeeper: FoundryGatekeeper):
#     """Verifies EVM exploitability."""
    
#     finding = state["findings"][0] if state.get("findings") else {}
#     if not finding:
#         return {"messages": [AIMessage(content="[GATEKEEPER]: No finding to verify.")]}
        
#     print(f"      [GATEKEEPER] Generating native EVM test suite for {finding.get('target_function')}...")
    
#     test_suite = gatekeeper.verifier_agent.generate_test_suite(
#         finding, state, state["user_contract"], f"{state['contract_name']}.sol"
#     )
    
#     qc_status = gatekeeper.execute_qc_validation(test_suite, debug_tag=f"{state['contract_name']}_verify")
    
#     if qc_status == "confirmed":
#         new_bug = {
#             "finding": finding,
#             "z3_result": state.get("z3_result"),
#             "bug_report": state.get("bug_report")
#         }
#         # Safely append to the list by returning the delta
#         current_bugs = state.get("verified_bugs", [])
#         return {
#             "verified_bugs": current_bugs + [new_bug],
#             "messages": [AIMessage(content="[GATEKEEPER]: Bug CONFIRMED in EVM execution.")]
#         }
#     elif qc_status == "property_held":
#         return {
#             "findings": [],
#             "messages": [AIMessage(content="[GATEKEEPER]: FALSE POSITIVE. Property held during EVM execution. Dropping finding.")]
#         }
#     else:
#         # Catch compile_failed, timeout, harness_error, etc.
#         # Do NOT clear the findings. Keep the bug active and force it to the Fixer/Formatter
#         # so it gets outputted to the user for manual review.
#         new_bug = {
#             "finding": finding,
#             "z3_result": state.get("z3_result"),
#             "bug_report": state.get("bug_report", "") + f"\n\n[QC CRITICAL WARNING] Gatekeeper failed to execute native EVM tests ({qc_status}). Z3 proved this bug, but dynamic verification could not compile/run. MANUAL REVIEW REQUIRED."
#         }
#         current_bugs = state.get("verified_bugs", [])
#         return {
#             "verified_bugs": current_bugs + [new_bug],
#             "messages": [AIMessage(content=f"[GATEKEEPER]: Execution failed ({qc_status}). Pushing Z3-proven bug to manual review.")]
#         }

def fixer_node(state: GraphState, fixer: FixerAgent, formatter: SubmissionFormatter):
    """Generates remediation code and compiles the report."""
    
    verified_bugs = state.get("verified_bugs", [])
    if not verified_bugs:
        return {"messages": [AIMessage(content="[FIXER]: No verified bugs to remediate.")]}
        
    latest_bug = verified_bugs[-1]
    finding = latest_bug["finding"]
    
    print(f"      [FIXER] Invoking high-reasoning agent for {finding.get('target_function')}...")
    
    fixed_code = fixer.generate_remediation(finding, state)
    
    report_md = formatter.compile_bounty_report(
        finding_idx=len(verified_bugs),
        stem=state["contract_name"],
        finding=finding,
        state=state,
        fixed_code=fixed_code
    )
    
    safe_func = finding.get("target_function", "unknown")
    report_path = os.path.join("output/submissions", f"{state['contract_name']}_{safe_func}_report.md")
    
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_md)
        msg = f"[FIXER]: Submission compiled and saved to {report_path}."
    except IOError as e:
        msg = f"[FIXER ERROR]: Failed to save report: {e}"
        
    return {
        "findings": [],
        "z3_code": "",
        "bug_report": None,
        "iterations": 0,
        "messages": [AIMessage(content=msg)]
    }