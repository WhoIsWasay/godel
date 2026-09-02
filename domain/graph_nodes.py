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
from domain.llm_utils import (EmptyResponseError, call_with_retry,
                              content_to_text, guarded_invoke)
from domain.semantics import compose_reachability_script, compose_script
from domain.z3_runner import run_z3
import uuid

logger = logging.getLogger(__name__)


def _parse_supervisor_decision(raw_content: str) -> dict:
    """Parse the supervisor's routing JSON from raw LLM output.

    Raises ValueError when no JSON object can be recovered (the caller
    forces a heal cycle). Defends against list-wrapped and scalar JSON,
    which previously crashed .get() or silently passed as approval."""
    from domain.json_extract import extract_json_value

    cleaned = re.sub(r'<think>.*?</think>', '', raw_content or "",
                     flags=re.DOTALL).strip()
    value, err = extract_json_value(cleaned)
    if value is None:
        raise ValueError(f"supervisor output had no JSON payload ({err})")
    if isinstance(value, list):
        value = value[0] if value else {}
    if not isinstance(value, dict):
        raise ValueError(
            f"Supervisor output is not a JSON object: {type(value).__name__}")
    return value


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
    raw_content = content_to_text(response.content).strip()

    try:
        decision = _parse_supervisor_decision(raw_content)
        status = decision.get("status", "APPROVED").upper()

        critique = decision.get("supervisor_critique") if status == "REJECTED" else None
        if status == "REJECTED" and not critique:
            # A rejection with no feedback would re-enter the hunter with a
            # None critique — indistinguishable from an approval. Force an
            # explicit heal signal instead.
            critique = ("Findings rejected but no critique was provided. "
                        "Re-derive each finding strictly from the contract "
                        "code and the CFG abstraction; drop anything you "
                        "cannot ground in a specific code location.")

        return {
            "supervisor_critique": critique,
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
    """Robust JSON extraction for one hunter pass.

    Returns (findings, parse_error, provider_empty):
      - findings: list of dicts extracted from the response (may be empty).
      - parse_error: human-readable error string, or None on success.
      - provider_empty: True iff the provider returned no usable payload
        (empty string, only <think>...</think> reasoning, or only empty
        markdown fences). This signal is distinct from "garbage JSON"
        so the caller can short-circuit outer retries — retrying on
        quota/rate-limit exhaustion only burns credits.
    """
    findings = []
    parse_error = None
    clean_response = re.sub(r'<think>.*?</think>', '', raw_response or "", flags=re.DOTALL).strip()

    # Early guard: the LLM sometimes returns only <think>...</think> tags
    # (reasoning trace with no JSON payload) or malformed markdown fences.
    # Catch the empty result here with a clear diagnostic instead of letting
    # json.loads('') cascade through three fallback layers as "char 0".
    if not clean_response:
        return [], "LLM response was empty after <think>-strip (reasoning-only output, no JSON payload)", True

    from domain.json_extract import extract_json_value

    value, err = extract_json_value(clean_response)
    if value is None:
        # Distinguish "provider gave us fences but no payload" (empty-ish
        # response, short-circuit outer retries) from genuine garbage JSON
        # (worth one bounded retry).
        if "```" in clean_response:
            parts = clean_response.split("```")
            inner = "".join(b for i, b in enumerate(parts) if i % 2 == 1)
            inner = re.sub(r"^[A-Za-z0-9_-]+[ \t]*\r?\n?", "", inner)
            if not inner.strip():
                return [], "LLM response contained only markdown fences with no JSON payload", True
        logger.warning("[BUG HUNTER] No JSON payload recovered from Isolator output: %s", err)
        return [], f"Could not extract a JSON payload from Isolator output ({err})", False

    if isinstance(value, dict):
        findings = value.get("findings", [])
    elif isinstance(value, list):
        findings = value

    if not isinstance(findings, list):
        findings = []
        parse_error = "Isolator output 'findings' was not a list."

    findings = [f for f in findings if isinstance(f, dict)]
    return findings, parse_error, False


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

    # --- Compositional context: cross-function state flow analysis ---
    compositional_context = ""
    try:
        from domain.abstracter import render_compositional_context
        static_analysis = state.get("slither_result")
        if static_analysis:
            compositional_context = render_compositional_context(static_analysis, focus_func)
            if compositional_context:
                logger.info("[BUG HUNTER] Compositional context injected for %s", focus_func)
    except Exception as e:
        logger.warning("compositional context generation failed (non-fatal): %s", e)

    # --- Attack-chain context: cross-boundary multi-step attacks ---
    # Distinct from compositional_context: flags chains where the attacker's
    # final exploit step happens OUTSIDE the contract (e.g., transferFrom
    # after an approve), which per-function analysis cannot prove.
    attack_chain_context = ""
    try:
        from domain.attack_chains import render_attack_chain_context
        static_analysis_for_chains = state.get("slither_result")
        if static_analysis_for_chains:
            attack_chain_context = render_attack_chain_context(
                static_analysis_for_chains, focus_func)
            if attack_chain_context:
                logger.info("[BUG HUNTER] Attack-chain context injected for %s", focus_func)
    except Exception as e:
        logger.warning("attack-chain context generation failed (non-fatal): %s", e)

    # --- Wrap probe signals: BitVec-256 overflow/underflow reachability ---
    wrap_context = ""
    wrap_signals = state.get("wrap_probe_signals")
    if wrap_signals:
        wrappable = [r for r in wrap_signals if r.get("wrap_reachable")]
        if wrappable:
            wrap_lines = ["<wrap_probe_signals>"]
            wrap_lines.append("  WARNING: The following storage writes can overflow/underflow")
            wrap_lines.append("  (BitVec-256 reachability confirmed; guards NOT assumed):")
            for w in wrappable:
                wrap_lines.append(f'  <wrappable write="{w["write"]}" />')
            wrap_lines.append("  Investigate these as potential overflow/underflow vectors.")
            wrap_lines.append("</wrap_probe_signals>")
            wrap_context = "\n".join(wrap_lines)

    # --- Paired CFG: cross-function reasoning for compositional pairs ---
    paired_cfg_context = ""
    paired_cfg = state.get("compositional_paired_cfg")
    if paired_cfg:
        paired_cfg_context = (
            "\n=== COMPOSITIONAL PAIR CFG (cross-function reasoning permitted) ===\n"
            f"{paired_cfg}\n"
            "You MAY report findings whose exploit requires state changes in BOTH "
            "functions shown above. The constraint must reference variables from both "
            "CFG slices.\n"
        )

    # Inject full contract reference, but STRICTLY bound the AI to the focus function
    input_text = f"""[CRITICAL INSTRUCTION]
You are actively auditing the function named: `{focus_func}`.
You MUST strictly evaluate this specific function. Do NOT report vulnerabilities found in other parts of the contract. The FULL CONTRACT REFERENCE is provided ONLY so you can cross-reference state variables and view/pure helpers.

A <cfg_abstraction> block may be present inside the isolation packet. It is DETERMINISTIC ground truth produced by a static analyzer (Slither): exact branch conditions, storage reads/writes, external calls, loop counts and High/Medium detector signals for this function (+callees). Your analysis MUST be consistent with it:
- Never claim a state variable is written (or an external call made) if the block says otherwise.
- Use its branch_conditions as candidate exploit boundaries to trace with boundary values.
- Treat detector <signal> entries as PRIORS to investigate, not as findings by themselves.
- If the block is absent or truncated, proceed from source only — do not invent CFG facts.

{compositional_context}
{attack_chain_context}
{wrap_context}
{paired_cfg_context}
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
    empty_passes = 0
    total_passes_attempted = 0
    for pass_i in range(passes):
        total_passes_attempted += 1
        try:
            raw_response = inspector._invoke(inspector.isolator_agent, inspector.isolator_prompt, input_text)
        except EmptyResponseError as e:
            # This pass produced only empty provider responses even after
            # low-level retries. Record it; other passes may still deliver.
            logger.error("[BUG HUNTER EMPTY RESPONSE] pass %d: %s", pass_i + 1, e)
            parse_errors.append(f"pass {pass_i + 1}: empty responses after retries ({e})")
            empty_passes += 1
            continue
        found, err, provider_empty = _parse_hunter_output(raw_response, inspector)
        all_findings.extend(found)
        if provider_empty:
            empty_passes += 1
        if err:
            parse_errors.append(f"pass {pass_i + 1}: {err}")
            if provider_empty:
                # Surface a visible diagnostic (not just logger) so the CI
                # log makes the root cause obvious instead of the cryptic
                # "char 0" cascade.
                print(f"      [BUG HUNTER PROVIDER EMPTY] pass {pass_i + 1}: {err}")
    
    # If EVERY pass came back empty (either EmptyResponseError or empty-after-
    # think-strip), signal the router to short-circuit — outer retries on
    # quota/rate-limit exhaustion only burn credits without producing output.
    hunter_provider_empty = (total_passes_attempted > 0
                             and empty_passes == total_passes_attempted)

    findings = all_findings
    if len(findings) > 1:
        for i, f in enumerate(findings, start=1):
            f.setdefault("id", i)
        findings = inspector.deduplicate(findings)
        print(f"      [BUG HUNTER] dedup across {passes} pass(es): {len(all_findings)} raw -> {len(findings)} unique findings")

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
        "hunter_provider_empty": hunter_provider_empty,
        "messages": [AIMessage(content=f"[BUG HUNTER]: Proposed {len(findings)} findings.")]
    }

def _active_harness(state: GraphState) -> dict | None:
    """Selects the best harness for the current finding: chain harness for
    compositional findings when available, otherwise the single-function harness."""
    finding = state.get("findings", [{}])[0] if state.get("findings") else {}
    chain = state.get("compositional_harness")
    if chain and (finding.get("class") == "compositional"
                  or "->" in str(finding.get("target_function", ""))):
        logger.info("[SPECIFIER] Using chain harness for compositional finding")
        return chain
    return state.get("semantic_harness")


def _grounded_intent(finding: dict) -> str:
    """A finding carries more grounding than `intent` alone: the invariant /
    root cause (`constraint`), the property or vulnerable slice (`relevant_code`),
    and — for a warm-seeded MCP re-confirm — a concrete `counterexample` the human
    already observed. build_prompt consumes ONLY `intent`, so fold the rest in.

    Dropping the witness is what left the specifier guessing and emitting
    [SUPERVISOR_ALERT] / blank code on a property the deterministic harness CAN
    express: the MiniVault deposit anti-dilution bug is provably SAT against the
    generated harness using the seed's own {assets:1, totalSupply:1,
    totalAssets:1000}, yet that counterexample never reached the prompt. The
    fixer and formatter already consume all three fields; the specifier should too."""
    intent = str(finding.get("intent", "") or "").strip()
    parts = []
    constraint = str(finding.get("constraint", "") or "").strip()
    if constraint:
        parts.append(f"Invariant / root cause to disprove: {constraint}")
    relevant = str(finding.get("relevant_code", "") or "").strip()
    if relevant:
        parts.append(f"Property / relevant code: {relevant}")
    cex = finding.get("counterexample")
    if isinstance(cex, dict) and cex:
        parts.append(
            "Concrete counterexample already observed — pin these values to "
            f"reproduce the violation, then generalize: {json.dumps(cex)}")
    if parts:
        intent = (intent + "\n\n" if intent else "") + "\n".join(parts)
    return intent


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
        {"intent": _grounded_intent(finding), "queries": rag_diag.get("queries", [])},
        state["user_contract"],
        rag_findings,
        semantic_harness=_active_harness(state),
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

def _probe_harness_vacuity(state: GraphState) -> str | None:
    """Vacuity probe for UNSAT verdicts. When a deterministic semantic
    harness exists, check that the model itself is satisfiable — an
    unreachable model makes any UNSAT meaningless. Returns the vacuity
    reason string, or None when the UNSAT is trustworthy (probe sat, or
    no harness: harness-less scripts are covered by the mandatory SANITY
    sentinel probe enforced in z3_runner)."""
    harness = _active_harness(state)
    if not (harness and harness.get("code")):
        return None
    vac_script = compose_reachability_script(harness)
    vac_result = run_z3(vac_script)
    if vac_result.get("status") == "sat":
        return None
    if vac_result.get("status") == "unsat":
        return ("harness model is unsatisfiable (guards contradict bounds "
                "or transitions) — property holds vacuously, NOT a real proof")
    return f"vacuity probe inconclusive ({vac_result.get('error', 'unknown')})"


def executor_node(state: GraphState, cegis_tool: CEGIS):
    """Executes the generated Z3 property."""
    
    z3_code = state.get("z3_code", "")
    if not z3_code:
        # The specifier produced no property: a blank LLM response with no
        # [SUPERVISOR_ALERT] (an alert is routed to the supervisor and never
        # reaches here). The old early-return set ONLY supervisor_critique +
        # messages — no z3_result, no counter increment — so route_after_executor
        # saw status=None, fell through to "specifier", and neither `iterations`
        # nor `executor_runs` ever advanced: an unbounded specifier->executor->
        # specifier loop stopped only by LangGraph's recursion_limit
        # (GraphRecursionError). That is exactly why the MCP seeded run reported
        # iterations=0 / analysis_incomplete. Mark it an error and count the
        # wasted round so route_after_executor's EXECUTOR_MAX_ITERATIONS bound
        # terminates it and the specifier gets bounded repair retries. Prefixing
        # the critique as executor feedback makes route_after_specifier send the
        # retry straight back to the executor (and specifier_node passes it on as
        # repair_feedback). This also closes the same latent loop in the main graph.
        return {
            "z3_result": {
                "status": "error",
                "error": "No Z3 code was provided to the executor.",
                "output": "",
            },
            "supervisor_critique": (
                "Z3 Syntax/Execution Error: No Z3 code was provided to the "
                "executor — the property script was empty. Regenerate a complete, "
                "runnable Z3 script that encodes the finding."
            ),
            "iterations": state.get("iterations", 0) + 1,
            "executor_runs": state.get("executor_runs", 0) + 1,
            "messages": [AIMessage(content="[EXECUTOR]: Failed. Missing Z3 code.")]
        }

    print(f"      [EXECUTOR] Running symbolic execution (Iteration {state.get('iterations', 0)})...")
    harness = _active_harness(state) or {}
    known_symbols = sorted((harness.get("symbols") or {}).keys())

    # Compose the deterministic harness with the LLM-authored property BEFORE
    # execution. The specifier returns the property block ALONE (it starts with
    # `solver, V = build_model()`); build_model is defined by the harness. Without
    # prepending it, the first run_z3 always NameErrors and CEGIS burns an LLM
    # repair call to improvise a standalone model — discarding the deterministic
    # bounds/guards/transitions and guessing uint256 ranges (huge witnesses that
    # overflow the Forge PoC). Skip when the property already carries its own
    # `def build_model` (the LLM sometimes echoes the harness) to avoid a
    # duplicate definition. state["z3_code"] stays property-only so proof.py is
    # readable; only the executed script is composed.
    runnable = z3_code
    if harness.get("code") and "def build_model" not in z3_code:
        runnable = compose_script(harness, z3_code)

    result = cegis_tool.run_with_repair(
        runnable,
        known_symbols=known_symbols,
        focus_function=state.get("current_focus_function"),
    )
    if result.get("repairs_used"):
        print(f"      [CEGIS] {result['repairs_used']} repair(s) applied inside executor")
    if result.get("deterministic_repairs"):
        print(f"      [CEGIS] {result['deterministic_repairs']} deterministic "
              f"NameError fix(es) applied without LLM")

    updates = {
        "z3_result": result,
        "iterations": state.get("iterations", 0) + 1,
        "executor_runs": state.get("executor_runs", 0) + 1,
        # Reset per-run so vacuity_status reflects ONLY the current execution.
        # Without this it is sticky: a later clean unsat/sat for a different
        # queued finding would still carry a stale "vacuous" flag, mislabeling
        # the terminal artifact and misrouting now that the router bounds on it.
        # The vacuous branch below overrides these back to "vacuous" when the
        # current run is vacuous.
        "vacuity_status": None,
        "vacuity_reason": None,
        "vacuity_unfixable": False,
    }

    if result["status"] == "sat":
        cex = result.get("counterexample") or {}
        cex_txt = ""
        if cex.get("assignments"):
            cex_txt = "\nConcrete counterexample assignments: " + ", ".join(
                f"{k}={v}" for k, v in sorted(cex["assignments"].items()))
        updates["bug_report"] = f"[Z3] Counterexample found:\n{result['output']}{cex_txt}"
        # Successful verdict: any leftover critique (e.g. an earlier Z3 error)
        # is stale — clear it so it cannot leak into the next specifier prompt
        # or detour routing through the supervisor.
        updates["supervisor_critique"] = None
        updates["messages"] = [AIMessage(content="[EXECUTOR]: SAT. Counterexample found. Passing to Gatekeeper.")]
    elif result["status"] == "unsat":
        vacuity_reason = _probe_harness_vacuity(state)
        if vacuity_reason:
            # Vacuous UNSAT: the base model itself is unreachable, so nothing
            # was proven. Keep the finding queued (never silently consume it)
            # and surface the incomplete artifact honestly.
            #
            # Two sub-cases:
            #  - The DETERMINISTIC harness is self-contradictory ("harness model
            #    is unsatisfiable"). compose_reachability_script probes the
            #    machine model alone, independent of the AI-written property, so
            #    it returns the SAME unsat every iteration. No specifier rewrite
            #    can fix it — flag vacuity_unfixable so the router ends at once
            #    instead of burning one LLM call per round (this is what spun
            #    withdraw to Iteration 88+ in CI).
            #  - Anything else (e.g. an inconclusive probe) stays on the bounded
            #    repair path via EXECUTOR_MAX_ITERATIONS.
            updates["vacuity_status"] = "vacuous"
            updates["vacuity_reason"] = vacuity_reason
            updates["vacuity_unfixable"] = vacuity_reason.startswith(
                "harness model is unsatisfiable")
            updates["supervisor_critique"] = (
                "Z3 VACUOUS MODEL: " + vacuity_reason
                + " Re-derive each state precondition from the contract code, "
                "ensure the base model alone is satisfiable, and regenerate "
                "the property."
            )
            print(f"      [VACUITY] {state.get('current_focus_function')}: {vacuity_reason}")
            updates["messages"] = [AIMessage(
                content=f"[EXECUTOR]: UNSAT but VACUOUS — {vacuity_reason}. Finding kept queued.")]
        else:
            remaining = state.get("findings", []) or []
            updates["findings"] = remaining[1:] if remaining else []
            if updates["findings"]:
                # Queue advanced to the next finding — give it a fresh executor
                # budget. Without this, the first finding can burn
                # EXECUTOR_MAX_ITERATIONS and starve every queued sibling.
                updates["executor_runs"] = 0
            updates["supervisor_critique"] = None
            updates["messages"] = [AIMessage(content="[EXECUTOR]: UNSAT. Property holds safely.")]
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
            "supervisor_critique": None,
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
            "supervisor_critique": None,
            "messages": [AIMessage(content="[GATEKEEPER]: Bug CONFIRMED in EVM execution.")]
        }
    elif qc_status == "confirmed_forced":
        new_bug = {
            "finding": finding,
            "z3_result": state.get("z3_result"),
            "bug_report": state.get("bug_report", "") + "\n\n[QC REACHABILITY WARNING] The invariant broke in the EVM, but ONLY after the PoC force-constructed the counterexample storage via vm.store/vm.etch. This proves the math is violable FROM that state; it does NOT prove the state is reachable through real public calls (it may be a spurious Z3 over-approximation). MANUAL REACHABILITY REVIEW REQUIRED.",
            "poc_test_code": test_suite,
            "forge_output": forge_output,
            "qc_status": qc_status,
            "unverified": True,
            "materialized_filename": real_filename,
        }
        current_bugs = state.get("verified_bugs", [])
        return {
            "verified_bugs": current_bugs + [new_bug],
            "findings": remaining_findings[1:],
            "executor_runs": 0,
            "supervisor_critique": None,
            "messages": [AIMessage(content="[GATEKEEPER]: Bug reproduced ONLY from a FORCED state (vm.store/etch). Reachability unproven — pushing to manual review, not a clean confirmation.")]
        }
    elif qc_status == "property_held":
        return {
            "findings": remaining_findings[1:],
            "executor_runs": 0,
            "supervisor_critique": None,
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
            "unverified": True,
            "materialized_filename": real_filename,
        }
        current_bugs = state.get("verified_bugs", [])
        return {
            "verified_bugs": current_bugs + [new_bug],
            "findings": remaining_findings[1:],
            "executor_runs": 0,
            "supervisor_critique": None,
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
        fixed_code=fixed_code,
        qc={
            "qc_status": latest_bug.get("qc_status", ""),
            "poc_test_code": latest_bug.get("poc_test_code", ""),
            "forge_output": latest_bug.get("forge_output", ""),
        },
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
                import re as _re
                pragma_m = _re.search(r"pragma solidity\s+\^?(\d+\.\d+\.\d+)",
                                      state.get("user_contract", ""))
                solc_ver = pragma_m.group(1) if pragma_m else "0.8.19"
                with open(toml_path, "w", encoding="utf-8") as f:
                    f.write("[profile.default]\n"
                            'src = "src"\n'
                            'out = "out"\n'
                            'libs = ["lib"]\n'
                            f'solc_version = "{solc_ver}"\n')

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