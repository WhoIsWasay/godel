# domain/graph_nodes.py

import os
import json
import re
import logging
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from domain import config
from domain.state import GraphState
from domain.inspector import Inspector
from domain.propertygenerator import PropertyGenerator
from domain.cegis import CEGIS
from domain.gatekeeper import FoundryGatekeeper
from domain.fixer import FixerAgent
from domain.formatter import SubmissionFormatter
from domain.schema import build_finding
from domain.llm_utils import EmptyResponseError, call_with_retry, guarded_invoke
from domain.semantics import compose_reachability_script
from domain.z3_runner import run_z3
import uuid

logger = logging.getLogger(__name__)


def supervisor_node(state: GraphState, llm_pro):
    """The brain of the graph. Evaluates findings to filter hallucinations early."""
    
    with open(config.PROMPTS_DIR / "supervisor_prompt.txt", "r", encoding="utf-8") as f:
        supervisor_prompt = f.read()

    # Inject the actual contract code and findings using the XML tags
    # the supervisor prompt's grounding_constraint references.
    state_summary = f"""TARGET FUNCTION UNDER ANALYSIS: {state.get('current_focus_function')}

<findings>
{json.dumps(state.get('findings', []), indent=2)}
</findings>

<contract>
{state.get('user_contract', '')}
</contract>
"""

    messages = [
        SystemMessage(content=supervisor_prompt),
        HumanMessage(content=f"Review the following proposed findings against the contract code:\n{state_summary}")
    ]

    response = call_with_retry(lambda: guarded_invoke(llm_pro, messages))
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

        # Defend against scalar/string JSON (e.g. '"APPROVED"') crashing on
        # .get() below — treat it as a parse failure and force a heal cycle.
        if not isinstance(decision, dict):
            raise ValueError(f"Supervisor output is not a JSON object: {type(decision).__name__}")

        status = decision.get("status", "APPROVED").upper()
        
        return {
            "supervisor_critique": decision.get("supervisor_critique") if status == "REJECTED" else None,
            "supervisor_runs": state.get("supervisor_runs", 0) + 1,
            "messages": [AIMessage(content=f"[SUPERVISOR]: {decision.get('thought_process', 'Evaluation complete.')}")]
        }
    except (json.JSONDecodeError, ValueError, AttributeError, TypeError) as e:
        logger.error("[SUPERVISOR JSON ERROR] %s. Forcing rejection to trigger heal.", e)
        return {
            "supervisor_critique": "Failed to parse routing JSON. You must output a valid JSON object.",
            "supervisor_runs": state.get("supervisor_runs", 0) + 1,
            "messages": [AIMessage(content="[SUPERVISOR ERROR]: Critical JSON structural parsing failure.")]
        }


def _parse_hunter_output(raw_response: str, inspector: Inspector):
    """Robust JSON extraction for one hunter pass. Returns (findings, parse_error)."""
    findings = []
    parse_error = None
    clean_response = re.sub(r'<think>.*?</think>', '', raw_response, flags=re.DOTALL).strip()

    # Early guard: the LLM sometimes returns only <think>...</think> tags
    # (reasoning trace with no JSON payload) or malformed markdown fences.
    # Catch the empty result here with a clear diagnostic instead of letting
    # json.loads('') cascade through three fallback layers as "char 0".
    if not clean_response:
        return [], "LLM response was empty after <think>-strip (reasoning-only output, no JSON payload)"

    try:
        if "```json" in clean_response:
            clean_response = clean_response.split("```json")[1].split("```")[0].strip()
        elif "```" in clean_response:
            clean_response = clean_response.split("```")[1].split("```")[0].strip()

        if not clean_response:
            return [], "LLM response contained only markdown fences with no JSON payload"

        # strict=False fixes the "Invalid control character" error natively
        parsed_data = json.loads(clean_response, strict=False)

        if isinstance(parsed_data, dict):
            findings = parsed_data.get("findings", [])
        elif isinstance(parsed_data, list):
            findings = parsed_data

    except json.JSONDecodeError as e:
        logger.warning("[BUG HUNTER] JSON Parse Error: %s. Falling back to Inspector extractor.", e)
        try:
            parsed_data = inspector.extract_json(raw_response)
            findings = parsed_data.get("findings", [])
            if not findings:
                # A genuine empty findings array parses on the primary path,
                # so empty-after-repair means the payload was garbage, not
                # clean — never let it masquerade as a safe verdict.
                parse_error = f"Primary JSON parse failed ({e}); fallback extractor recovered no findings."
        except Exception as fallback_err:
            findings = []
            parse_error = f"Primary JSON parse failed ({e}); fallback extractor failed ({fallback_err})."

    if not isinstance(findings, list):
        findings = []
        parse_error = "Isolator output 'findings' was not a list."

    findings = [f for f in findings if isinstance(f, dict)]
    return findings, parse_error


def bug_hunter_node(state: GraphState, inspector: Inspector):
    """Invokes the Isolator to find bugs, with robust JSON defense and strict function scoping."""

    xml_packet = state.get("isolated_xml_packet", "")
    full_code = state.get("user_contract", "")
    readme = state.get("readme_specs", "")
    critique = state.get("supervisor_critique")
    focus_func = state.get("current_focus_function")

    # --- RAG: retrieve historical vulnerability patterns for this function ---
    rag_context = ""
    try:
        from domain.rag import retrieve_findings_for_hunter
        rag_findings, rag_diag = retrieve_findings_for_hunter(
            focus_func, contract_code=full_code, final_top_k=5
        )
        if rag_findings:
            lines = []
            mandatory_lines = []
            for rf in rag_findings:
                sev = rf.get("severity", "?").upper()
                title = rf.get("title_normalized", "")
                desc = rf.get("description", "")[:300]
                sim = rf.get("cosine_score") or rf.get("rerank_score") or 0.0
                entry = f"- [{sev}] {title}: {desc}"
                if sim >= 0.6:
                    mandatory_lines.append(f"- [MANDATORY INVESTIGATE] [{sev}] {title}: {desc}")
                else:
                    lines.append(entry)
            rag_context = "\n\n=== KNOWN VULNERABILITY PATTERNS (from historical audits) ===\n"
            if mandatory_lines:
                rag_context += "The following patterns have HIGH RELEVANCE to this function. "
                rag_context += "You MUST flag each as a finding — the Z3 solver will verify. "
                rag_context += "Do NOT dismiss them:\n"
                rag_context += "\n".join(mandatory_lines)
                rag_context += "\n"
            if lines:
                rag_context += "\nAdditional patterns to CHECK:\n"
                rag_context += "\n".join(lines)
    except Exception as e:
        logger.warning("hunter RAG retrieval failed (non-fatal): %s", e)
    
    # Inject full contract reference, but STRICTLY bound the AI to the focus function
    input_text = f"""[CRITICAL INSTRUCTION]
You are actively auditing the function named: `{focus_func}`. 
You MUST strictly evaluate this specific function. Do NOT report vulnerabilities found in other parts of the contract. The FULL CONTRACT REFERENCE is provided ONLY so you can cross-reference state variables and view/pure helpers.

A <cfg_abstraction> block may be present inside the isolation packet. It is DETERMINISTIC ground truth produced by a static analyzer (Slither): exact branch conditions, storage reads/writes, external calls, loop counts and High/Medium detector signals for this function (+callees). Your analysis MUST be consistent with it:
- Never claim a state variable is written (or an external call made) if the block says otherwise.
- Use its branch_conditions as candidate exploit boundaries to trace with boundary values.
- Treat detector <signal> entries as PRIORS to investigate, not as findings by themselves.
- If the block is absent or truncated, proceed from source only — do not invent CFG facts.

=== SYSTEM README ===
{readme}

=== TARGET ISOLATION PACKET ===
{xml_packet}

=== FULL CONTRACT REFERENCE (For internal helper calls) ===
{full_code}{rag_context}"""

    if critique:
        input_text += f"\n\n[SUPERVISOR CRITIQUE]: {critique}\nFix your previous analysis based on this feedback."

    retry_n = state.get("hunter_retries", 0)
    if retry_n > 0:
        input_text += (
            f"\n\n[RETRY NOTICE — attempt {retry_n + 1}] Your previous response could not be parsed."
            "\nOutput STRICT JSON only: a single object with a 'findings' array, no prose, "
            "no markdown fences beyond ```json, no trailing commas, all strings double-quoted."
        )

    passes = max(1, config.HUNTER_PASSES)
    all_findings = []
    parse_errors = []
    for pass_i in range(passes):
        try:
            raw_response = inspector._invoke(inspector.isolator_agent, inspector.isolator_prompt, input_text)
        except EmptyResponseError as e:
            # This pass produced only empty provider responses even after
            # low-level retries. Record it; other passes may still deliver.
            logger.error("[BUG HUNTER EMPTY RESPONSE] pass %d: %s", pass_i + 1, e)
            parse_errors.append(f"pass {pass_i + 1}: empty responses after retries ({e})")
            continue
        found, err = _parse_hunter_output(raw_response, inspector)
        all_findings.extend(found)
        if err:
            parse_errors.append(f"pass {pass_i + 1}: {err}")
    
    findings = all_findings
    if passes > 1 and len(findings) > 1:
        for i, f in enumerate(findings, start=1):
            f.setdefault("id", i)
        findings = inspector.deduplicate(findings)
        print(f"      [BUG HUNTER] {passes} passes merged: {len(all_findings)} raw -> {len(findings)} unique findings")

    # Every pass failed and nothing was recovered: this must never
    # masquerade as a clean safety verdict — flag it so routing retries
    # at graph level or aborts as analysis_failed. Partial success
    # (findings recovered despite a failed pass) is accepted.
    parse_error = "; ".join(parse_errors) if (parse_errors and not findings) else None
    if parse_error:
        logger.error("[BUG HUNTER] All %d pass(es) failed to produce findings — flagged as analysis failure, NOT as 'safe'.", passes)

    if not isinstance(findings, list):
        findings = []
        parse_error = "Isolator output 'findings' was not a list."

    if not findings and not parse_error:
        logger.info("[BUG HUNTER] No vulnerabilities detected in %s. Exiting early.", state.get('current_focus_function'))
    elif parse_error:
        # Never let malformed LLM output masquerade as a clean safety verdict.
        logger.error("[BUG HUNTER PARSE FAILURE] %s", parse_error)
        logger.error("[BUG HUNTER] Could not parse Isolator output — flagged as analysis failure, NOT as 'safe'.")

    return {
        "findings": findings,
        "hunter_parse_error": parse_error,
        "hunter_retries": (retry_n + 1) if parse_error else 0,
        "messages": [AIMessage(content=f"[BUG HUNTER]: Proposed {len(findings)} findings.")]
    }

def specifier_node(state: GraphState, generator: PropertyGenerator):
    """Translates the finding into a Z3 property."""
    
    finding = state["findings"][0] if state.get("findings") else {}
    
    # --- RAG: pull historical vulnerability findings to enrich the Z3 prompt ---
    rag_findings, rag_diag = [], {}
    try:
        from domain.rag import retrieve_findings_for_specifier
        rag_findings, rag_diag = retrieve_findings_for_specifier(
            finding, final_top_k=5, top_k_per_query=10
        )
    except Exception as e:
        logger.warning("specifier RAG retrieval failed (non-fatal): %s", e)

    generator.build_prompt(
        {"intent": finding.get("intent", ""), "queries": rag_diag.get("queries", [])},
        state["user_contract"],
        rag_findings,
        semantic_harness=state.get("semantic_harness"),
        repair_feedback=state.get("supervisor_critique"),
    )
    
    z3_code_raw = generator.propertyGeneration()
    
    if "[SUPERVISOR_ALERT]" in z3_code_raw:
        return {
            "supervisor_critique": z3_code_raw,
            "z3_code": "",
            "rag_diagnostics": rag_diag,
            "messages": [AIMessage(content=z3_code_raw)]
        }
    else:
        return {
            "z3_code": z3_code_raw,
            "rag_diagnostics": rag_diag,
            "messages": [AIMessage(content="[SPECIFIER]: Z3 Property Generated.")]
        }

def _handle_unsat_verdict(state: GraphState, updates: dict) -> None:
    """UNSAT verdict handling. When a deterministic semantic harness exists,
    probe it for vacuity (an unreachable model makes UNSAT meaningless).
    Harness-less scripts are covered by the mandatory SANITY sentinel probe
    enforced in z3_runner, so a plain UNSAT there is trusted."""
    harness = state.get("semantic_harness")
    if harness and harness.get("code"):
        vac_script = compose_reachability_script(harness)
        vac_result = run_z3(vac_script)
        if vac_result.get("status") == "sat":
            # Model satisfiable without property -> genuine proof
            updates["messages"] = [AIMessage(content="[EXECUTOR]: UNSAT. Property holds safely.")]
        elif vac_result.get("status") in ("unsat", "error", "inconclusive"):
            # Model itself is unsatisfiable or could not be checked ->
            # the UNSAT property result may be vacuous
            reason = (
                "harness model is unsatisfiable (guards contradict bounds "
                "or transitions) — property holds vacuously, NOT a real proof"
                if vac_result.get("status") == "unsat"
                else f"vacuity probe inconclusive ({vac_result.get('error', 'unknown')})"
            )
            updates["vacuity_status"] = "vacuous"
            updates["vacuity_reason"] = reason
            print(f"      [VACUITY] {state.get('current_focus_function')}: {reason}")
            updates["messages"] = [AIMessage(
                content=f"[EXECUTOR]: UNSAT but VACUOUS — {reason}")]
        else:
            updates["messages"] = [AIMessage(content="[EXECUTOR]: UNSAT. Property holds safely.")]
    else:
        updates["messages"] = [AIMessage(content="[EXECUTOR]: UNSAT. Property holds safely.")]


def executor_node(state: GraphState, cegis_tool: CEGIS):
    """Executes the generated Z3 property."""
    
    z3_code = state.get("z3_code", "")
    if not z3_code:
        return {
            "supervisor_critique": "No Z3 code was provided to the executor.",
            "messages": [AIMessage(content="[EXECUTOR]: Failed. Missing Z3 code.")]
        }

    print(f"      [EXECUTOR] Running symbolic execution (Iteration {state.get('iterations', 0)})...")
    result = cegis_tool.run_with_repair(z3_code)
    if result.get("repairs_used"):
        print(f"      [CEGIS] {result['repairs_used']} repair(s) applied inside executor")

    updates = {
        "z3_result": result,
        "iterations": state.get("iterations", 0) + 1,
        "executor_runs": state.get("executor_runs", 0) + 1,
    }

    if result["status"] == "sat":
        cex = result.get("counterexample") or {}
        cex_txt = ""
        if cex.get("assignments"):
            cex_txt = "\nConcrete counterexample assignments: " + ", ".join(
                f"{k}={v}" for k, v in sorted(cex["assignments"].items()))
        updates["bug_report"] = f"[Z3] Counterexample found:\n{result['output']}{cex_txt}"
        updates["messages"] = [AIMessage(content="[EXECUTOR]: SAT. Counterexample found. Passing to Gatekeeper.")]
    elif result["status"] == "unsat":
        remaining = state.get("findings", []) or []
        updates["findings"] = remaining[1:] if remaining else []
        if updates["findings"]:
            # Queue advanced to the next finding — give it a fresh executor
            # budget. Without this, the first finding can burn
            # EXECUTOR_MAX_ITERATIONS and starve every queued sibling.
            updates["executor_runs"] = 0
        _handle_unsat_verdict(state, updates)
    elif result["status"] == "vacuous":
        # SANITY probe failed: the base model is over-constrained, so every
        # check was vacuously UNSAT. Keep the finding queued and feed explicit
        # repair guidance back to the specifier — never accept this as safe.
        updates["supervisor_critique"] = (
            "Z3 VACUOUS MODEL: "
            + (result.get("error") or "the SANITY probe returned unsat.")
            + " The preconditions contradict each other or over-constrain the "
            "state so no reachable model exists. Re-derive each state "
            "precondition from the contract code, ensure the base model alone "
            "is satisfiable, and regenerate the property."
        )
        updates["messages"] = [AIMessage(
            content="[EXECUTOR]: VACUOUS — over-constrained base model. Regenerating property.")]
    else:
        updates["supervisor_critique"] = f"Z3 Syntax/Execution Error:\n{result['error']}"
        updates["messages"] = [AIMessage(content="[EXECUTOR]: ERROR during execution. Needs refinement.")]
        
    return updates



def gatekeeper_node(state: GraphState, gatekeeper: FoundryGatekeeper):
    """Verifies EVM exploitability."""

    # Defensive ordering: check for a finding BEFORE consulting the scope
    # filter (is_finding_in_scope dereferences the dict).
    remaining_findings = state.get("findings", []) or []
    finding = remaining_findings[0] if remaining_findings else {}
    if not finding:
        return {"messages": [AIMessage(content="[GATEKEEPER]: No finding to verify.")]}
    if not gatekeeper.is_finding_in_scope(finding, state):
        # Consume this finding but keep any others queued for verification.
        return {
            "findings": remaining_findings[1:],
            "executor_runs": 0,
            "messages": [AIMessage(content="[GATEKEEPER]: Finding out of scope. Dropped.")]
        }
        
    # =====================================================================
    # --- MATERIALIZE FILE FOR FOUNDRY (with guaranteed cleanup) ---
    # A stale src/ file with unresolved imports breaks compilation for every
    # subsequent forge run, so the file is removed in a finally block.
    real_contract_name = FoundryGatekeeper.extract_contract_name(
        state["user_contract"], fallback=state.get('contract_name')
    )
    try:
        target_src_file = gatekeeper.materialize_source(state["user_contract"], real_contract_name)
        materialized = True
    except Exception as e:
        logger.warning("[GATEKEEPER WARNING] Failed to materialize source file: %s", e)
        target_src_file = None
        materialized = False

    try:
        return _gatekeeper_verify(state, gatekeeper, finding, remaining_findings,
                                  real_contract_name, target_src_file)
    finally:
        if materialized:
            gatekeeper.cleanup_source(target_src_file)


def _gatekeeper_verify(state, gatekeeper, finding, remaining_findings,
                       real_contract_name, target_src_file):
    """Core verification path; separated so src/ cleanup always runs above."""

    print(f"      [GATEKEEPER] Generating native EVM test suite for {finding.get('target_function')}...")
    
    # Per-finding artifact dir: all gatekeeper debug output lands here (task #17).
    # Unique suffix prevents overloaded functions (same name, different
    # signatures) racing on the same folder across threads.
    finding_dir = os.path.join(
        str(config.SUBMISSIONS_FOLDER),
        state.get("contract_name", "unknown"),
        f"{finding.get('target_function', 'unknown')}_{uuid.uuid4().hex[:6]}",
    )
    os.makedirs(finding_dir, exist_ok=True)

    # Pass the real filename we just created to the Verifier agent
    real_filename = os.path.basename(target_src_file) if target_src_file else f"{real_contract_name}.sol"
    test_suite = gatekeeper.verifier_agent.generate_test_suite(
        finding, state, state["user_contract"], real_filename
    )

    from domain.solc_compat import needs_legacy_harness
    legacy = needs_legacy_harness(state["user_contract"])
    if legacy:
        print("      [GATEKEEPER] Legacy solc target detected — using forge-std-free verification harness.")
    qc_status, forge_output = gatekeeper.execute_qc_validation(
        test_suite, debug_tag=f"{real_contract_name}_verify", debug_dir=finding_dir,
        legacy=legacy, target_source=state["user_contract"])
    
    if qc_status == "confirmed":
        new_bug = {
            "finding": finding,
            "z3_result": state.get("z3_result"),
            "bug_report": state.get("bug_report"),
            "poc_test_code": test_suite,
            "forge_output": forge_output,
            "qc_status": qc_status,
            "materialized_filename": real_filename,
        }
        current_bugs = state.get("verified_bugs", [])
        return {
            "verified_bugs": current_bugs + [new_bug],
            "findings": remaining_findings[1:],
            "executor_runs": 0,
            "messages": [AIMessage(content="[GATEKEEPER]: Bug CONFIRMED in EVM execution.")]
        }
    elif qc_status == "property_held":
        return {
            "findings": remaining_findings[1:],
            "executor_runs": 0,
            "messages": [AIMessage(content="[GATEKEEPER]: FALSE POSITIVE. Property held during EVM execution. Dropping finding.")]
        }
    else:
        new_bug = {
            "finding": finding,
            "z3_result": state.get("z3_result"),
            "bug_report": state.get("bug_report", "") + f"\n\n[QC CRITICAL WARNING] Gatekeeper failed to execute native EVM tests ({qc_status}). Z3 proved this bug, but dynamic verification could not compile/run. MANUAL REVIEW REQUIRED.",
            "poc_test_code": test_suite,
            "forge_output": forge_output,
            "qc_status": qc_status,
            "materialized_filename": real_filename,
        }
        current_bugs = state.get("verified_bugs", [])
        return {
            "verified_bugs": current_bugs + [new_bug],
            "findings": remaining_findings[1:],
            "executor_runs": 0,
            "messages": [AIMessage(content=f"[GATEKEEPER]: Execution failed ({qc_status}). Pushing Z3-proven bug to manual review.")]
        }

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

    contract_name = state.get("contract_name", "unknown")
    function_name = finding.get("target_function", "unknown")
    # Unique suffix: overloaded functions (same name, different signatures)
    # would otherwise race two threads writing the same folder.
    folder_path = os.path.join(
        str(config.SUBMISSIONS_FOLDER), contract_name,
        f"{function_name}_{uuid.uuid4().hex[:6]}"
    )
    os.makedirs(folder_path, exist_ok=True)

    finding_dict = build_finding(
        finding,
        state,
        fixed_code,
        latest_bug.get("poc_test_code", ""),
        latest_bug.get("forge_output", ""),
        latest_bug.get("qc_status", ""),
    )

    files_to_write = {
        "finding.json": json.dumps(finding_dict, indent=4),
        "report.md": report_md,
        "proof.py": state.get("z3_code", ""),
        "PoC.t.sol": latest_bug.get("poc_test_code", ""),
        "forge_output.log": latest_bug.get("forge_output", ""),
        "isolated_slice.sol": finding.get("relevant_code", ""),
    }

    try:
        for filename, content in files_to_write.items():
            file_path = os.path.join(folder_path, filename)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)

        # Re-materialize the contract source so PoC.t.sol's
        # `import "src/<filename>.sol"` resolves. The gatekeeper's temporary
        # copy was cleaned up in its finally block; this is the durable copy.
        materialized_filename = latest_bug.get("materialized_filename")
        if materialized_filename:
            src_dir = os.path.join(folder_path, "src")
            os.makedirs(src_dir, exist_ok=True)
            src_path = os.path.join(src_dir, materialized_filename)
            with open(src_path, "w", encoding="utf-8") as f:
                f.write(state.get("user_contract", ""))
            # Minimal foundry.toml so `forge test` works after a one-time
            # `forge install foundry-rs/forge-std` inside the artifact folder.
            toml_path = os.path.join(folder_path, "foundry.toml")
            if not os.path.exists(toml_path):
                with open(toml_path, "w", encoding="utf-8") as f:
                    f.write("[profile.default]\n"
                            'src = "src"\n'
                            'out = "out"\n'
                            'libs = ["lib"]\n'
                            'solc_version = "0.8.19"\n')

        print(f"Successfully created folder '{folder_path}' and wrote {len(files_to_write)} files.")
            
        msg = f"[FIXER]: Submission compiled and saved."
    except IOError as e:
        msg = f"[FIXER ERROR]: Failed to save report: {e}"

    # Copy-on-write: never mutate the shared state dict in place (bypasses
    # channel reducers; fragile under checkpointing).
    updated_bugs = [dict(b) for b in verified_bugs]
    updated_bugs[-1]["fix_code"] = fixed_code

    return {
        "verified_bugs": updated_bugs,
        # Do NOT clear "findings" here: with multi-finding processing, any
        # still-queued findings must survive so routing can continue them.
        "z3_code": "",
        "bug_report": None,
        "supervisor_critique": None,
        "iterations": 0,
        "messages": [AIMessage(content=msg)]
    }