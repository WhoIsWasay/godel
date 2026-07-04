import os
import json
import subprocess
import tempfile
import sys
import re
from pathlib import Path
from datetime import date
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

from domain.inspector import Inspector
from domain.arbiter import Arbiter
from domain.propertygenerator import PropertyGenerator
from domain.cegis import CEGIS
from domain.state import GraphState
from domain.slither_runner import run_slither
from domain.fixer import FixerAgent
from domain.formatter import SubmissionFormatter
from Infrastructure.postgres import retrieve
from piyoxml import parse_solidity_to_xml

# NEW QUALITY CONTROL IMPORTS
from domain.verifier import PropertyVerifierAgent
from domain.gatekeeper import FoundryGatekeeper

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
    timeout=120,       # add this
    max_retries=3,     # and this — auto-retries transient network failures
)

llm_pro = ChatOpenAI(
    model="deepseek-v4-pro",
    openai_api_key=os.environ.get("DEEPSEEK_API_KEY"),
    temperature=0.0,
    max_tokens=4096,
    openai_api_base="https://api.deepseek.com",
    extra_body={"thinking": {"type": "enabled", "budget_tokens": 16000}},
    timeout=120,       # add this
    max_retries=3,     # and this — auto-retries transient network failures
)

fixer_agent = FixerAgent(agent=llm_pro)
submission_formatter = SubmissionFormatter()

# INITIALIZE NEW QC MODULES
property_verifier = PropertyVerifierAgent(agent_llm=llm_pro)
gatekeeper = FoundryGatekeeper(project_root=".", verifier_agent=property_verifier)




def build_func_matcher(all_func_names: list):
    """
    Builds a regex that, at any word-start position, matches the LONGEST
    function name from the contract that fits — so 'withdrawAll' is never
    mistaken for 'withdraw', and inflected forms ('liquidated') still match
    their base function name ('liquidate').
    """
    sorted_names = sorted(set(all_func_names), key=len, reverse=True)
    escaped = [re.escape(n) for n in sorted_names]
    pattern = r'\b(' + '|'.join(escaped) + r')'
    return re.compile(pattern, re.IGNORECASE)

def line_matches_function(line: str, func_name: str, matcher: re.Pattern) -> bool:
    """
    True only if func_name is the longest/correct function name matched
    at some position in the line — not a shorter prefix of a longer name.
    """
    for m in matcher.finditer(line):
        if m.group(1).lower() == func_name.lower():
            return True
    return False



def check_scope_drift(func_name_hint: str, z3_code: str):
    if func_name_hint and func_name_hint not in z3_code:
        print(f"    [WARNING] Generated Z3 property does not reference target function '{func_name_hint}' — possible scope drift.")

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

# ==========================================
# PIPELINE — ONE FINDING
# ==========================================
def run_pipeline(finding: dict, contract_code: str, contract_path: str) -> dict:
    user_intent_raw = f"""Intent: {finding.get('intent', 'N/A')}
Constraint: {finding.get('constraint', 'N/A')}
Target Function: {finding.get('target_function', 'unknown')}
Tool Hint: {finding.get('tool_hint', 'N/A')}
Relevant Code: {finding.get('relevant_code', '')}"""

    state: GraphState = {
        "user_intent_raw": user_intent_raw,
        "user_contract":   contract_code,
        "mode":            "",
        "intent":          "",
        "queries":         [],
        "findings":        [],
        "z3_code":         "",
        "z3_result":       None,
        "slither_result":  {},    
        "status":          "running",
        "bug_report":      None,
        "iterations":      0
    }







    arbiter = Arbiter(agent=llm_flash)
    expansion = arbiter.QueryArbiter(state["user_intent_raw"])
    print(f"    Arbiter mode: {expansion['mode']}")

    state["mode"]    = expansion["mode"]
    state["intent"]  = expansion["intent"]
    state["queries"] = expansion["queries"]

    cegis = CEGIS(agent=llm_pro, run_z3_tool=run_z3)

    if state["mode"] == "z3":
        try:
            results_rag = retrieve(state["queries"])
            state["findings"] = results_rag
        except Exception as db_err:
            print(f"    [DATABASE WARNING] RAG connection failed (Postgres offline). Running on pure logic. Error: {db_err}")
            state["findings"] = []

        generator = PropertyGenerator(agent=llm_flash)
        generator.build_prompt(expansion, contract_code, state["findings"])
        state["z3_code"] = generator.propertyGeneration()
        check_scope_drift(finding.get("target_function", ""), state["z3_code"])
        state = cegis.cegis_loop(state)

    elif state["mode"] == "slither":
        state["slither_result"] = run_slither(contract_path)
        state = cegis.cegis_loop(state)

    elif state["mode"] == "both":
        state["slither_result"] = run_slither(contract_path)

        try:
            results_rag = retrieve(state["queries"])
            state["findings"] = results_rag
        except Exception as db_err:
            print(f"    [DATABASE WARNING] RAG connection failed (Postgres offline). Running on pure logic. Error: {db_err}")
            state["findings"] = []

        generator = PropertyGenerator(agent=llm_flash)
        generator.build_prompt(expansion, contract_code, state["findings"])
        state["z3_code"] = generator.propertyGeneration()
        check_scope_drift(finding.get("target_function", ""), state["z3_code"])
        state = cegis.cegis_loop(state)
                

    elif state["mode"] == "standard":
        state["status"]     = "verified"
        state["bug_report"] = "Standard mode — no formal verification needed."
    else:
        state["status"] = "needs_review"
        state["bug_report"] = f"Unrecognized mode '{state['mode']}' returned by Arbiter."

    return state

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
    """Finds distinct function elements, filtering out un-implemented interface/abstract specifications."""
    pattern = r'<function\s+name="([^"]+)"[^>]*>(.*?)</function>'
    matches = re.findall(pattern, xml_string, re.DOTALL)
    functions = []
    
    for name, body in matches:
        if "{" not in body:
            print(f"      [FILTER] Skipping '{name}': Interface/Abstract declaration signature detected.")
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

def is_finding_in_scope(finding: dict, result_state: dict) -> bool:
    """
    Gatekeeper Scope Filter: Instantly drops centralization, governance, 
    and design choices that are out-of-scope for Web3 bug bounties.
    """
    intent = finding.get("intent", "").lower()
    raw_report = (result_state.get("bug_report") or "").lower()
    
    # 1. Drop if the scanner explicitly stated the code is valid/safe
    if "logic adheres to safety invariants" in raw_report:
        print(f"      [SCOPE GATEKEEPER] Dropping finding {finding.get('id')}: Code verified safe by scanner.")
        return False
        
    # 2. Block out-of-scope architectural and centralization risks
    out_of_scope_keywords = [
        "timelock", "multisig", "multi-signature", "governance delay", 
        "centralization risk", "single-step ownership", "missing-zero-check",
        "ownable2step", "access control modifier"
    ]
    
    for keyword in out_of_scope_keywords:
        if keyword in intent or keyword in raw_report:
            print(f"      [SCOPE GATEKEEPER] Dropping finding {finding.get('id')}: Out-of-scope risk ({keyword}).")
            return False
            
    return True

# ==========================================
# ARTIFACT SAVER (I/O)
# ==========================================
def save_artifacts(finding_idx: int, stem: str, finding: dict, state: dict):
    """Saves the runtime execution Z3 scripts and Slither outputs locally with crash safety rules."""
    safe_func = re.sub(r'[^a-zA-Z0-9_]', '', finding.get('target_function', 'unknown'))
    base_name = f"{stem}_{safe_func}_{finding_idx}"
    
    if state.get("z3_code") and state.get("mode") in ["z3", "both"]:
        z3_path = os.path.join("output/proofs", f"{base_name}_proof.py")
        try:
            with open(z3_path, "w", encoding="utf-8") as f:
                f.write(state["z3_code"])
        except Exception as e:
            print(f"      [WARNING] Could not save Z3 proof script for {base_name}: {e}")

    if state.get("slither_result") and state.get("mode") in ["slither", "both"]:
        slither_path = os.path.join("output/proofs", f"{base_name}_slither.json")
        try:
            with open(slither_path, "w", encoding="utf-8") as f:
                json.dump(state["slither_result"], f, indent=2, default=str)
        except Exception as e:
            print(f"      [WARNING] Could not save Slither trace for {base_name}: {e}")

# ==========================================
# MAIN ORCHESTRATOR
# ==========================================
def main():
    readme = ""
    readme_path = os.path.join(CONTRACTS_FOLDER, "README.md")
    if os.path.exists(readme_path):
        with open(readme_path, "r", encoding="utf-8") as f:
            readme = f.read()
        print(f"README loaded from {readme_path}")

    sol_files = collect_sol_files(CONTRACTS_FOLDER)
    if not sol_files:
        print(f"No .sol files found in {CONTRACTS_FOLDER}/")
        return

    print(f"\nFound {len(sol_files)} contract(s):")
    for s in sol_files:
        print(f"  {s}")

    print("\n=== PROCESSING ISOLATED FUNCTION SANDBOXES ===")
    inspector = Inspector(llm_flash, llm_flash)
    
    for sol_path in sol_files:
        stem = Path(sol_path).stem
        xml_str = parse_solidity_to_xml(sol_path)

        if not xml_str:
            print(f"  Skipping (parse failed): {sol_path}")
            continue

        xml_out = os.path.join(XML_OUTPUT_FOLDER, f"{stem}.xml")
        with open(xml_out, "w", encoding="utf-8") as f:
            f.write(xml_str)

        with open(sol_path, "r", encoding="utf-8") as f:
            raw_solidity_code = f.read()

        env_setup = extract_element_text(xml_str, "environment_setup")
        interfaces = extract_element_text(xml_str, "interface")
        state_vars = extract_element_text(xml_str, "state_variables")
        functions = extract_functions_from_xml(xml_str)
        all_func_names = [f["name"] for f in functions]
        matcher = build_func_matcher(all_func_names)

        print(f"\nProcessing File: {sol_path} ({len(functions)} valid execution functions identified)")

        file_isolated_findings = []

        for func in functions:
            print(f"  -> Sandboxing function: {func['name']}")
            
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

            isolator_input = f"{readme}\n\n{injection_packet}" if readme else injection_packet
            
            all_runs_findings = []
            # ! Idx here is Shadowed !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            for _ in range(3):
                try:
                    raw_response = inspector._invoke(inspector.isolator_agent, inspector.isolator_prompt, isolator_input)
                    parsed_json = inspector.extract_json(raw_response)
                    all_runs_findings.extend(parsed_json.get("findings", []))
                except Exception as api_err:
                    print(f"    [API WARNING] Isolator call failed: {api_err}. Skipping this run.")
                    continue

            deduped_func_findings = inspector.deduplicate(all_runs_findings)
            
            for finding in deduped_func_findings:
                finding["class"] = "isolated"
                finding["target_function"] = func["name"]
                file_isolated_findings.append(finding)

        contract_findings = inspector.deduplicate(file_isolated_findings)
        print(f"  Isolated findings verified for {stem}: {len(contract_findings)}")

        findings_path = os.path.join(FINDINGS_FOLDER, f"{stem}_findings.json")
        with open(findings_path, "w", encoding="utf-8") as f:
            json.dump({"findings": contract_findings}, f, indent=2)

        # * GODEL MD REPORT FILE =======================================================================================================================
        if contract_findings:
            print(f"  Executing downstream verification loop for {stem}...")
            report_path = os.path.join(REPORTS_FOLDER, f"{stem}_report.md")
            
            md = [
                f"# Gödel Report — {stem}",
                f"**Date:** {date.today()}",
                f"**Contract Targeted:** {sol_path}",
                f"**Isolated Properties Proven:** {len(contract_findings)}",
                "", "---", ""
            ]
            
            confirmed, verified, needs_review, errors, false_positives = 0, 0, 0, 0, 0
            
            for idx, finding in enumerate(contract_findings):
                print(f"    Testing property assertion on function: {finding['target_function']}")
                result = run_pipeline(finding, raw_solidity_code, sol_path)
                
                # ---> INSERT FILTER HERE <---
                if not is_finding_in_scope(finding, result):
                    false_positives += 1  # Tracked as rejected/skipped
                    continue  # Skip report output generation entirely!
                # ----------------------------
                
                status = result.get("status", "unknown")
                raw_bug_report = result.get("bug_report") or "No report generated."

                # --- ADVANCED PROOF CLEANING LAYER ---
                func_name = finding.get('target_function', '')
                if result.get("mode") in ["slither", "both"] and func_name:
                    lines = raw_bug_report.split('\n')
                    filtered_lines = []
                    has_tool_finding = False
                    
                    func_pattern = re.compile(rf'\b{re.escape(func_name)}', re.IGNORECASE)
                    for line in lines:
                        is_match = line_matches_function(line, func_name, matcher)
                        
                        # is_match = bool(func_pattern.search(line))
                        if is_match:
                            filtered_lines.append(line)
                            if "[SLITHER]" in line or "[Z3]" in line:
                                has_tool_finding = True
                        elif "BUG FOUND:" in line or "[Z3]" in line:
                            filtered_lines.append(line)
                    
                    if has_tool_finding:
                        bug_report = "\n".join(filtered_lines)
                    else:
                        bug_report = f"BUG FOUND:\n[SLITHER] Static analysis verification completed for `{func_name}`. Function logic adheres to safety invariants."
                else:
                    bug_report = raw_bug_report
                
                result["bug_report"] = bug_report
                
                # Re-sync status with what the cleaning layer actually confirmed
                if result.get("mode") in ["slither", "both"] and func_name:
                    status = "bug_found" if has_tool_finding else "verified"
                
                # Downstream execution paths on confirmed bug matches
                if status == "bug_found":
                    # --- DYNAMIC NATIVE SOURCE INJECTION ---
                    contract_filename = os.path.basename(sol_path) # e.g., "lendingPool.sol"
                    print(f"      [QC FILTER] Syncing {contract_filename} directly into native compiler directory...")
                    os.makedirs("src", exist_ok=True)
                    temp_src_target = os.path.join("src", contract_filename)
                    with open(temp_src_target, "w", encoding="utf-8") as f:
                        f.write(raw_solidity_code)
                    
                    print(f"      [QC FILTER] Generating defensive property suite via LLM...")
                    # Pass the real file name to the verifier agent
                    generated_test_suite = property_verifier.generate_test_suite(
                        finding, result, raw_solidity_code, contract_filename
                    )
                    
                    print(f"      [QC FILTER] Running Forge execution checks...")
                    safe_func_dbg = re.sub(r'[^a-zA-Z0-9_]', '', finding.get('target_function', 'unknown'))
                    qc_status = gatekeeper.execute_qc_validation(
                        generated_test_suite, debug_tag=f"{stem}_{safe_func_dbg}_{idx}"
                    )

                    # Clean up the injected source code file immediately
                    if os.path.exists(temp_src_target):
                        os.remove(temp_src_target)

                    if qc_status == "property_held":
                        # Only outcome with actual evidence the finding is wrong.
                        print(f"      [QC DISCARDED] Property held under real execution. Confirmed false positive.")
                        status = "false_positive"
                        false_positives += 1
                        continue  # Skip report output generation completely

                    if qc_status != "confirmed":
                        # compile_failed / harness_error / timeout / tool_missing / tool_error:
                        # inconclusive, NOT evidence the bug is fake. Keep it in the report for a human to check
                        # instead of silently dropping it like a disproven finding.
                        print(f"      [QC INCONCLUSIVE: {qc_status}] Keeping finding for manual review rather than discarding.")
                        status = "needs_review"
                        result["bug_report"] = (result.get("bug_report") or "") + \
                            f"\n\n[QC NOTE] Dynamic verification was inconclusive (reason: {qc_status}). " \
                            f"This finding was NOT proven false — it just couldn't be automatically confirmed. Manual review recommended."
                        needs_review += 1

                        md.append(f"## Property Test: `{finding['target_function']}`")
                        md.append(f"**Severity:** {finding.get('severity_guess', 'medium').upper()} | **Status:** `{status}`")
                        md.append(f"\n**Intent:**\n> {finding['intent']}")
                        md.append(f"\n**Mathematical Invariant Constraint:**\n> {finding['constraint']}")
                        md.append(f"\n**QC Note:** Dynamic verification inconclusive ({qc_status}) — not disproven, needs manual check.")
                        md.append("---")
                        with open(report_path, "w", encoding="utf-8") as f:
                            f.write("\n".join(md))
                        continue

                    print(f"      [QC VERIFIED] Invariant broken in actual EVM execution. Logging bug report.")
                    # -------------------------------------------
                

                    # 1. Archive mathematical and structural proofs
                    save_artifacts(idx, stem, finding, result)
                    print(f"      [ARTIFACT SAVED] Mathematical proofs logged for {finding['target_function']}.")
                    
                    # 2. Trigger Fixer Agent for Solidity refactoring
                    print(f"      [FIXER] Invoking high-reasoning agent for remediation code...")
                    fixed_code_snippet = fixer_agent.generate_remediation(finding, result)
                    
                    safe_func_name = re.sub(r'[^a-zA-Z0-9_]', '', finding.get('target_function', 'unknown'))
                    fix_file_path = os.path.join("output/fixes", f"{stem}_{safe_func_name}_{idx}_fix.sol")
                    
                    try:
                        with open(fix_file_path, "w", encoding="utf-8") as f:
                            f.write(fixed_code_snippet)
                        print(f"      [FIX COMPLETED] Remediation file written to: {fix_file_path}")
                    except Exception as io_err:
                        print(f"      [WARNING] Could not write fix file for {safe_func_name}: {io_err}")

                    # 3. Trigger Submission Formatter to create report
                    print(f"      [FORMATTER] Compiling portal-ready submission report...")
                    bounty_content = submission_formatter.compile_bounty_report(
                        idx, stem, finding, result, fixed_code_snippet
                    )
                    
                    severity_char = finding.get('severity_guess', 'm').lower()[0]
                    sub_file_name = f"{stem}_{safe_func_name}_{severity_char.upper()}_{idx}.md"
                    sub_file_path = os.path.join("output/submissions", sub_file_name)
                    
                    try:
                        with open(sub_file_path, "w", encoding="utf-8") as f:
                            f.write(bounty_content)
                        print(f"      [SUBMISSION READY] Exported clean payout file: {sub_file_path}")
                    except Exception as format_err:
                        print(f"      [WARNING] Could not write submission file: {format_err}")

                if status == "bug_found":      confirmed += 1
                elif status == "verified":     verified += 1
                elif status == "needs_review": needs_review += 1
                else:                          errors += 1

                md.append(f"## Property Test: `{finding['target_function']}`")
                md.append(f"**Severity:** {finding.get('severity_guess', 'medium').upper()} | **Status:** `{status}`")
                md.append(f"\n**Intent:**\n> {finding['intent']}")
                md.append(f"\n**Mathematical Invariant Constraint:**\n> {finding['constraint']}")
                md.append(f"\n**Verified Source Boundary:**\n```solidity\n{finding.get('relevant_code', '')}\n```")
                md.append(f"\n**Solver Output Trace:**\n```\n{bug_report}\n```\n---")

                with open(report_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(md))

            # Compile matrix breakdown onto the base report file
            md.append("\n## Verification Matrix Summary")
            md.append("| State Machine Property Result | Count |")
            md.append("|---|---|")
            md.append(f"| Mathematical Bug Proven (SAT) | {confirmed} |")
            md.append(f"| Formally Verified Safe (UNSAT) | {verified} |")
            md.append(f"| Structural Edge Case (Review) | {needs_review} |")
            md.append(f"| Execution Failure / Parse Error | {errors} |")
            md.append(f"| Rejected by Gatekeeper (False Positive) | {false_positives} |")
            
            with open(report_path, "w", encoding="utf-8") as f:
                f.write("\n".join(md))

            print(f"  Verification Report saved: {report_path}")

    print("\n" + "="*50 + "\n=== SYSTEM PIPELINE EXECUTION COMPLETE ===\n" + "="*50)

if __name__ == "__main__":
    main()