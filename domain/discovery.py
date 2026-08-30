"""domain/discovery.py — Phase C: LLM-proposed, machine-verified invariant discovery.

Gödel's verification half was already deterministic (Phase 2/3); its discovery
half was human-gated (--invariant required a hand-written expression). This
module closes that gap with the cheapest sound architecture available:

    1. A fast LLM reads STATIC FACTS ONLY (storage layout, guards, writes) and
       proposes candidate invariants in the harness V-key grammar.
    2. Proposals are filtered by symbol validation (garbage dies here, free).
    3. Every survivor runs through check_invariant_preservation() — Z3 proves
       or refutes it across ALL public functions. The LLM cannot hallucinate
       its way past this step: a "broken" proposal carries a machine-found
       counterexample; a "proven" one carries an UNSAT certificate.

Output buckets:
    proven        -> published as discovered-and-verified properties
    broken        -> routed toward findings (violation + violating function)
    inconclusive  -> reported honestly (PARTIAL models), never claimed
    rejected      -> failed syntax/symbol validation before any solving

Deterministic except step 1. Default model: fast/cheap (GODEL_DISCOVERY_MODEL).
"""
import json
import logging
import os
import re

from domain.invariants import (check_invariant_preservation,
                               _referenced_keys, InvariantSyntaxError)
from domain.semantics import generate_harness
from domain.llm_utils import call_with_retry, guarded_invoke

logger = logging.getLogger(__name__)


def default_discovery_llm():
    """Fast client for proposal generation (thinking disabled)."""
    from langchain_openai import ChatOpenAI

    model = os.environ.get("GODEL_DISCOVERY_MODEL", "").strip() or "deepseek-v4-flash"
    return ChatOpenAI(
        model=model,
        openai_api_key=os.environ.get("DEEPSEEK_API_KEY"),
        temperature=0.0,
        max_tokens=4000,
        openai_api_base=os.environ.get("DISCOVERY_API_BASE", "https://api.deepseek.com"),
        extra_body={"thinking": {"type": "disabled"}},
        timeout=120,
        max_retries=3,
    )


def fact_sheet(analysis: dict) -> str:
    """Compact deterministic description of the contract for the proposer."""
    lines = [f"contract {analysis.get('contract', '?')} {{"]
    for v in analysis.get("storage_layout", []):
        lines.append(f"    storage {v['type']} {v['name']};")
    for fn, f in analysis.get("functions", {}).items():
        mods = " ".join(f["modifiers"])
        lines.append(f"    function {fn} {f['visibility']} {mods} {{")
        for g in f.get("guards", []):
            txt = g if isinstance(g, str) else g.get("text", "")
            lines.append(f"        require {txt}")
        for w in f.get("state_writes", []):
            lines.append(f"        writes {w}")
        lines.append("    }")
    lines.append("}")
    return "\n".join(lines)


def _union_keys(analysis: dict) -> list[str]:
    keys: list[str] = []
    for fn in analysis.get("functions", {}):
        h = generate_harness(analysis, fn)
        if h:
            keys.extend(h["symbols"].keys())
    seen, uniq = set(), []
    for k in keys:
        if k not in seen:
            seen.add(k)
            uniq.append(k)
    return uniq


def _system_prompt(keys: list[str], max_invariants: int) -> str:
    return f"""You are an invariant PROPOSER for a Solidity formal verifier.

TASK: Propose up to {max_invariants} MEANINGFUL contract invariants that SHOULD hold
for the contract below (e.g. conservation, solvency, bounds, agreement between paired fields).

NEVER propose pure monotonicity ("X@new >= X" or "X@new <= X" for a single field):
mutable state legitimately moves in both directions (deposits AND withdrawals), so such
proposals are trivially refutable noise.

STRICT GRAMMAR (violations are auto-rejected):
- Python/Z3 boolean expressions over EXACTLY these symbols: {keys}
- Post-state values use the '@new' suffix (e.g. total@new). Plain names = pre-state/call args.
- Allowed operators: == != <= >= < > and or not + - *
- NO function calls, no attributes, no subscripts beyond the given key forms, no literals > 10**9.
- Each invariant must be non-trivial (relate two fields, or bound a field away from degenerate values).

OUTPUT: JSON only, shape {{"invariants": ["expr1", "expr2"]}}"""


def _extract_json(raw: str) -> dict:
    s = (raw or "").strip()
    if "```json" in s:
        s = s.split("```json")[1].split("```")[0]
    elif "```" in s:
        s = s.split("```")[1].split("```")[0]
    try:
        return json.loads(s.strip())
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", s, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                pass
    return {}


_PURE_MONOTONICITY = re.compile(
    r"^\s*(?P<a>[A-Za-z_][\w.\[\]#]*)\s*@\s*new\s*(?:>=|<=|>|<)\s*(?P=a)\s*$"
    r"|^\s*(?P<b>[A-Za-z_][\w.\[\]#]*)\s*(?:>=|<=|>|<)\s*(?P=b)\s*@\s*new\s*$",
    re.IGNORECASE,
)


def propose_invariants(analysis: dict, llm, max_invariants: int = 6) -> tuple[list[str], list[str]]:
    """Returns (valid_proposals, rejected_with_reason)."""
    keys = _union_keys(analysis)
    if not keys:
        return [], [("all", "no harness symbols available")]
    prompt = _system_prompt(keys[:40], max_invariants)
    user = fact_sheet(analysis)
    try:
        resp = call_with_retry(lambda: guarded_invoke(llm, [
            ("system", prompt), ("user", user)]))
        content = resp.content if hasattr(resp, "content") else str(resp)
    except Exception as e:
        logger.warning("[DISCOVERY] proposer LLM failed (non-fatal): %s", e)
        return [], [("all", f"llm error: {e}")]

    data = _extract_json(content)
    valid, rejected = [], []
    seen = set()
    for inv in (data.get("invariants") or [])[:max_invariants]:
        if not isinstance(inv, str) or not inv.strip():
            continue
        inv = inv.strip()
        if inv.lower() in seen:
            continue
        seen.add(inv.lower())
        if _PURE_MONOTONICITY.match(inv):
            # Junk class observed in the wild (ping-test run): "X@new >= X" over
            # mutable state is refuted by any legitimate setter/withdrawal, so it
            # always produces HIGH-severity false positives. Kill it pre-solver.
            rejected.append((inv, "pure monotonicity over mutable state — not a "
                                  "protocol invariant (legitimate operations move it both ways)"))
            continue
        refs = _referenced_keys(inv, keys)
        if not refs:
            rejected.append((inv, "references no known symbols"))
            continue
        try:
            probe_harness = None
            for fn in analysis.get("functions", {}):
                h = generate_harness(analysis, fn)
                if h and any(k in h["symbols"] for k in refs):
                    probe_harness = h
                    break
            if probe_harness is None:
                rejected.append((inv, "no harness covers its symbols"))
                continue
            from domain.invariants import validate_syntax
            validate_syntax(inv, probe_harness)
        except InvariantSyntaxError as e:
            rejected.append((inv, str(e)))
            continue
        valid.append(inv)
    return valid, rejected


def discover_invariants(analysis: dict, llm, max_invariants: int = 6) -> dict:
    """Full loop: propose -> validate -> verify -> classify."""
    proposals, rejected = propose_invariants(analysis, llm, max_invariants)
    proven, broken, inconclusive = [], [], []

    for inv in proposals:
        report = check_invariant_preservation(analysis, inv)
        verdict = report.get("verdict", "")
        entry = {
            "invariant": inv,
            "verdict": verdict,
            "violated_by": report.get("violated_by", []),
            "possibly_violated_by": report.get("possibly_violated_by", []),
            "preserved_in": report.get("preserved_in", []),
            "vacuously_preserved_in": report.get("vacuously_preserved_in", []),
        }
        if verdict == "INVARIANT BROKEN":
            # Attach machine-found counterexamples from the FULL-model hits.
            cex_list = []
            for d in report.get("details", []):
                if d.get("status") == "violated" and d.get("counterexample"):
                    cex_list.append({
                        "function": d["function"],
                        "assignments": (d["counterexample"] or {}).get("assignments", {}),
                    })
            entry["counterexamples"] = cex_list
            broken.append(entry)
        elif verdict.startswith("INVARIANT PRESERVED"):
            proven.append(entry)
        else:
            inconclusive.append(entry)

    return {
        "contract": analysis.get("contract"),
        "proven": proven,
        "broken": broken,
        "inconclusive": inconclusive,
        "rejected": [{"invariant": i, "reason": r} for i, r in rejected],
    }
