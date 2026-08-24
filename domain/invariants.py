"""domain/invariants.py — Phase 3: contract-wide invariant preservation mode.

Verifies that a user-supplied contract invariant is PRESERVED by every public
state-changing function, using the deterministic Z3 harnesses from
domain.semantics (Phase 2). This is the induction step of invariant-based
formal verification, done WITHOUT any LLM:

    assume Inv(pre-state)  ==>  prove Inv(post-state)  (per function)

A function BREAKS the invariant when: Inv(pre) ∧ guards ∧ transitions ⊨ ¬Inv(new)
is satisfiable. SAT = violated by that function (with concrete counterexample);
UNSAT = preserved (or vacuously — see LIMITATIONS).

Invariant syntax: plain Python/Z3 boolean expression over harness V-keys,
where POST-state variables carry the '@new' suffix, e.g.:

    "total@new == bal[A]@new + bal[B]@new"
    "total@new >= 0 and debt[msg.sender...]"          (see symbols per function)

Keys without '@new' refer to the pre-state / call arguments (identical on both
sides of the transition). Run per-file against the analysis cache:

    from domain.invariants import check_invariant_preservation
    result = check_invariant_preservation(analysis, "total@new >= 0")

LIMITATIONS (honest scope of v1):
  - Vacuity is NOT checked: if Inv(pre) is unreachable through a function's
    guards, UNSAT may mean 'vacuously preserved'.
  - Functions whose harness quality is PARTIAL give weaker guarantees (UNSAT
    under over-approximation is still sound).
"""

import logging

from domain.semantics import generate_harness
from domain.z3_runner import run_z3

logger = logging.getLogger(__name__)


class InvariantSyntaxError(ValueError):
    pass


def _wrap_keys(expr_text: str, keys: list[str]) -> str:
    """Wraps every known V-key occurring in expr_text into V['key'].
    Longest keys are substituted first via \x00-sentinels so nested names
    ('totalGranted' inside 'totalGranted@new') never double-wrap."""
    ordered = sorted(set(keys), key=len, reverse=True)
    out = expr_text
    tokens = {}
    for i, key in enumerate(ordered):
        tok = f"\x00{i}\x00"
        tokens[tok] = key
        out = out.replace(key, tok)
    for tok, key in tokens.items():
        out = out.replace(tok, f"V[{key!r}]")
    return out


def _key_regex(key: str):
    import re

    return re.compile(re.escape(key))


def validate_syntax(expr_text: str, harness: dict) -> None:
    """Raises InvariantSyntaxError if the expression references no known keys
    or contains characters outside the allowed safe subset."""
    if not expr_text or not expr_text.strip():
        raise InvariantSyntaxError("empty invariant")
    forbidden = {";", "import", "__", "exec", "eval", "open(", "system"}
    low = expr_text.lower()
    for tok in forbidden:
        if tok in low:
            raise InvariantSyntaxError(f"forbidden token in invariant: {tok!r}")
    hits = sum(1 for k in harness["symbols"] if k in expr_text)
    if hits == 0:
        raise InvariantSyntaxError(
            f"invariant references none of the model symbols "
            f"(available: {sorted(harness['symbols'])[:12]}...)")


def _referenced_keys(invariant: str, union_keys: list[str]) -> list[str]:
    """Keys actually referenced by the invariant text (longest-match, so
    'totalGranted@new' wins over 'totalGranted')."""
    found = []
    text = invariant
    for k in sorted(set(union_keys), key=len, reverse=True):
        if k in text:
            found.append(k)
            text = text.replace(k, "\x00")
    return found


def _py_to_z3_bool(expr: str) -> str:
    """Python's 'and'/'or' cannot combine Z3 BoolRefs (raises
    'Symbolic expressions cannot be cast to concrete Boolean values' at
    runtime). Rewrites top-level boolean connectives into And()/Or() calls.
    Handles flat mixtures; nested-parenthesization precedence beyond that is
    outside the v1 invariant grammar."""
    if " or " in expr:
        parts = [p.strip() for p in expr.split(" or ")]
        return "Or(" + ", ".join(_py_to_z3_bool(p) for p in parts) + ")"
    if " and " in expr:
        parts = [p.strip() for p in expr.split(" and ")]
        return "And(" + ", ".join(_py_to_z3_bool(p) for p in parts) + ")"
    return expr


def _inv_codes(harness: dict, invariant: str, referenced: list[str]):
    """Returns (inv_new_code, inv_pre_code) — Z3-python for the invariant over
    post-state keys and over pre-state keys ('@new' collapsed), respectively.
    Only referenced keys present in this harness's symbol table are wrapped."""
    sym_keys = list(harness["symbols"].keys())
    inv_new_keys = [k for k in referenced if k in sym_keys]
    inv_new = _wrap_keys(invariant, inv_new_keys)
    pre_src = invariant.replace("@new", "")
    pre_keys = sorted({k.replace("@new", "") for k in inv_new_keys}, key=len, reverse=True)
    inv_pre = _wrap_keys(pre_src, pre_keys)
    return _py_to_z3_bool(inv_new), _py_to_z3_bool(inv_pre)


def _compose_preservation_script(harness: dict, invariant: str,
                                 referenced: list[str],
                                 identity_keys: list[str] = None) -> str:
    """Builds a runnable script. Invariant expressions are evaluated at module
    level right after build_model() returns — every referenced symbol must be
    present in this harness's V (check_function guarantees that).

    `identity_keys` = referenced '@new' keys this function cannot modify; each
    is pinned new == old, which is semantically exact for untouched storage."""
    sym_keys = list(harness["symbols"].keys())
    inv_new, inv_pre = _inv_codes(harness, invariant, referenced)

    identity_lines = []
    for k in (identity_keys or []):
        pre_k = k.replace("@new", "")
        if k in sym_keys and pre_k in sym_keys:
            identity_lines.append(f"solver.add(V[{k!r}] == V[{pre_k!r}])")

    return (
        harness["code"]
        + "\n\n"
        + "solver, V = build_model()\n"
        + "\n".join(identity_lines)
        + ("\n" if identity_lines else "")
        + f"INV_PRE = ({inv_pre})\n"
        + f"INV_NEW = ({inv_new})\n"
        + "solver.add(INV_PRE)\n"
        + "solver.add(Not(INV_NEW))\n"
        + "if solver.check() == sat:\n"
        + "    print(\"BUG FOUND:\", solver.model())\n"
        + "else:\n"
        + "    print(\"Property holds\")\n"
    )


def _compose_vacuity_script(harness: dict, inv_pre_code: str,
                            identity_keys: list[str] = None) -> str:
    """Probe: is Inv(pre) reachable at all through this function's guards?
    UNSAT here means every 'preserved' answer for this function is VACUOUS
    (the antecedent is impossible), which must be reported as such rather
    than presented as a genuine preservation proof."""
    sym_keys = list(harness["symbols"].keys())
    identity_lines = []
    for k in (identity_keys or []):
        pre_k = k.replace("@new", "")
        if k in sym_keys and pre_k in sym_keys:
            identity_lines.append(f"solver.add(V[{k!r}] == V[{pre_k!r}])")

    return (
        harness["code"]
        + "\n\n"
        + "solver, V = build_model()\n"
        + "\n".join(identity_lines)
        + ("\n" if identity_lines else "")
        + f"solver.add({inv_pre_code})\n"
        # Sentinels keep their z3_runner meanings: SAT = antecedent reachable
        # (prints BUG FOUND), UNSAT = antecedent impossible ("Property holds").
        + "if solver.check() == sat:\n"
        + "    print(\"BUG FOUND:\", solver.model())\n"
        + "else:\n"
        + "    print(\"Property holds\")\n"
    )


def check_function(analysis: dict, function_name: str, invariant: str,
                   referenced: list[str]) -> dict:
    """Checks invariant preservation for ONE function.
      violated             : SAT under an EXACT model — genuinely broken
      possibly_violated    : SAT under an over-approximated (PARTIAL) model
      preserved            : UNSAT — holds even with havocked unknowns
      preserved_readonly   : function never writes any referenced state
      not_modeled          : writes referenced state its model can't represent
                             -> conservatively inconclusive"""
    facts = analysis.get("functions", {}).get(function_name, {})
    harness = generate_harness(analysis, function_name)

    writes = set(facts.get("state_writes", []))
    touched = {k.split("@")[0].split("[")[0] for k in referenced}

    if harness is None:
        status = "not_modeled" if (writes & touched) else "preserved_readonly"
        return {"function": function_name, "status": status,
                "quality": None, "counterexample": None}

    sym_keys = list(harness["symbols"].keys())
    # State this function provably cannot modify gets pinned new == old.
    def _base(k):
        return k.split("@")[0].split("[")[0]

    identity_keys = [k for k in referenced
                     if k in sym_keys and _base(k) not in writes]
    missing = [k for k in referenced
               if k not in sym_keys and k.replace("@new", "") not in sym_keys]
    unreferencable = [k for k in missing
                      if _base(k) not in {_base(s) for s in sym_keys}]
    unmodeled_writes = [k for k in missing if _base(k) in writes]
    if unmodeled_writes or unreferencable:
        return {"function": function_name, "status": "not_modeled",
                "quality": harness["quality"], "counterexample": None}

    script = _compose_preservation_script(harness, invariant, referenced,
                                          identity_keys)
    result = run_z3(script)

    out = {
        "function": function_name,
        "quality": harness["quality"],
        "untranslated": harness["untranslated"],
        "counterexample": None,
    }
    if result["status"] == "sat":
        from domain.cegis import CEGIS

        out["counterexample"] = CEGIS.extract_counterexample(result.get("output") or "")
        if harness["quality"] == "FULL":
            out["status"] = "violated"
        else:
            out["status"] = "possibly_violated"
    elif result["status"] == "unsat":
        # UNSAT preservation can be genuine OR vacuous (Inv(pre) unreachable).
        # Probe the antecedent alone; never sell a vacuous proof as real.
        _, inv_pre = _inv_codes(harness, invariant, referenced)
        vac = run_z3(_compose_vacuity_script(harness, inv_pre, identity_keys))
        if vac.get("status") == "unsat":
            out["status"] = "vacuously_preserved"
            out["vacuity_reason"] = ("Inv(pre) is unsatisfiable through this "
                                     "function's guards — nothing was proven")
        else:
            out["status"] = "preserved"
    else:
        out["status"] = result["status"]  # error / inconclusive
        out["error"] = result.get("error")
    return out


def check_invariant_preservation(analysis: dict, invariant: str,
                                 functions: list[str] = None) -> dict:
    """Checks an invariant across all (or selected) functions of a contract.
    Returns an aggregate report. Raises InvariantSyntaxError if the invariant
    matches NO function's symbol space at all."""
    if analysis is None:
        raise ValueError("no static analysis available")

    all_fns = list(analysis.get("functions", {}).keys())

    # Union of every symbol key across all function models — the invariant
    # must reference at least one known state symbol somewhere.
    union_keys: list[str] = []
    for fn in (functions or all_fns):
        h = generate_harness(analysis, fn)
        if h:
            union_keys.extend(h["symbols"].keys())
    referenced = _referenced_keys(invariant, union_keys)
    if not referenced:
        raise InvariantSyntaxError(
            f"invariant references no known symbols of any function "
            f"(functions: {all_fns[:10]})")

    results = [check_function(analysis, fn, invariant, referenced)
               for fn in (functions or all_fns)]
    violated = [r for r in results if r["status"] == "violated"]
    preserved = [r for r in results if r["status"] == "preserved"]
    vacuous = [r for r in results if r["status"] == "vacuously_preserved"]
    inconclusive = [r for r in results
                    if r["status"] in ("possibly_violated", "not_modeled",
                                       "error", "inconclusive")]

    if violated:
        verdict = "INVARIANT BROKEN"
    elif inconclusive:
        verdict = "INCONCLUSIVE"
    elif preserved:
        exact = all(r.get("quality") == "FULL" for r in preserved)
        verdict = ("INVARIANT PRESERVED (exact)" if exact
                   else "INVARIANT PRESERVED (under over-approximation)")
        # Vacuity never upgrades a verdict — it is surfaced as a caveat list.
        if vacuous:
            verdict += f" — {len(vacuous)} function(s) vacuously preserved"
    else:
        # Only vacuous (and/or read-only) results: NOTHING was actually proven.
        verdict = ("VACUOUS ONLY — no function's pre-state satisfies the "
                   "invariant; no preservation was proven")

    return {
        "contract": analysis.get("contract"),
        "invariant": invariant,
        "verdict": verdict,
        "violated_by": [r["function"] for r in violated],
        "possibly_violated_by": [r["function"] for r in results
                                 if r["status"] == "possibly_violated"],
        "preserved_in": [r["function"] for r in preserved],
        "vacuously_preserved_in": [r["function"] for r in vacuous],
        "errors": inconclusive,
        "details": results,
    }
