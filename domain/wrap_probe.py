"""domain/wrap_probe.py — opt-in BitVec-256 wraparound reachability probe.

The main encoder models uint256 as unbounded Int (SOUND over-approximation:
UNSAT proofs stay valid), which means it can never SEE overflow-wrap bugs.
This probe complements it: for every storage arithmetic write found by the
static layer it asks Z3, over REAL 256-bit words, whether a single call can
wrap the value.

Scope (honest v1):
  - Guards are intentionally NOT assumed -> results are a conservative
    triage list for the unbounded-Int blind spot, NOT confirmed exploits.
  - Only storage-targeting writes are probed; pure-local arithmetic cannot
    corrupt contract state and is out of scope.
  - '-' probes unsigned underflow (Old < A); '+'/'*' probe overflow.

Deterministic, LLM-free. Enable via:
    python main.py --wrap-probe --contracts <folder>
"""
import re

from domain.z3_runner import run_z3


def _literal(tok: str):
    tok = tok.strip()
    return int(tok) if re.fullmatch(r"\d+", tok) else None


def _arithmetic_writes(facts: dict) -> list[dict]:
    """Compound ops (+=/-=) plus plain '=' whose RHS is one binary op."""
    out = []
    for a in facts.get("assignments", []):
        op = a.get("op")
        lhs = (a.get("lhs") or "").strip()
        rhs = (a.get("rhs") or "").strip()
        if op in ("+=", "-="):
            out.append({"lhs": lhs, "op": op[0], "operand": rhs})
            continue
        if op == "=":
            m = re.match(r"^(.+?)\s*([+\-*])\s*(.+)$", rhs)
            if m:
                l, r = m.group(1).strip(), m.group(3).strip()
                if not any(x in l + r for x in ("(", ")", ".", "[")):
                    out.append({"lhs": lhs, "op": m.group(2),
                                "operand": f"{l}&&{r}"})
    return out


def _resolve_operand(operand: str, param_names: list[str]):
    """Returns ('param', name) | ('lit', int) | None."""
    parts = [x.strip() for x in operand.split("&&")] if "&&" in operand else [operand.strip()]
    for p in parts:
        if p in param_names:
            return ("param", p)
    for p in parts:
        v = _literal(p)
        if v is not None:
            return ("lit", v)
    return None


def _probe_script(op: str, use_arg: bool, lit: int = None) -> str:
    """Single-operation BitVec-256 reachability query (EVM unsigned words)."""
    lines = ["from z3 import *", "Old = BitVec('Old', 256)", "s = Solver()"]
    if use_arg:
        lines.insert(2, "A = BitVec('A', 256)")
        A = "A"
    else:
        lines.insert(2, f"A = BitVecVal({lit}, 256)")
        A = "A"
    cond = {
        "+": f"Old + {A} < Old",
        "-": f"ULT(Old, {A})",
        "*": f"And({A} > 1, Old > 1, Old * {A} < Old)",
    }[op]
    lines.append(f"s.add({cond})")
    lines.append('if s.check() == sat:')
    lines.append('    print("BUG FOUND:", s.model())')
    lines.append('else:')
    lines.append('    print("Property holds")')
    return "\n".join(lines)


def probe_function(analysis: dict, function_name: str) -> list[dict]:
    """Returns one row per storage arithmetic write with wrap reachability."""
    facts = analysis.get("functions", {}).get(function_name)
    if not facts:
        return []
    state_vars = {v.split("[")[0].strip() for v in
                  (facts.get("state_writes", []) + facts.get("state_reads", []))}
    param_names = [p["name"] for p in facts.get("params", [])
                   if str(p.get("type", "")).startswith("uint")]

    rows = []
    for w in _arithmetic_writes(facts):
        lhs_base = w["lhs"].split("[")[0].strip()
        if lhs_base not in state_vars:
            continue  # only storage writes matter for wrap corruption

        resolved = _resolve_operand(w["operand"], param_names)
        if resolved is None:
            continue
        kind, val = resolved
        script = _probe_script(w["op"], use_arg=(kind == "param"), lit=val)
        res = run_z3(script)
        shown = val if kind == "param" else f"{val}"
        rows.append({
            "function": function_name,
            "write": f"{w['lhs']} {w['op']}= {shown}"
                     + ("" if kind == "param" else " (const)"),
            "wrap_reachable": res.get("status") == "sat",
            "verdict_status": res.get("status"),
        })
    return rows


def probe_contract(analysis: dict) -> list[dict]:
    rows = []
    for fn in analysis.get("functions", {}):
        rows.extend(probe_function(analysis, fn))
    return rows
