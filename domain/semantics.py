"""domain/semantics.py — Phase 2 deterministic semantic encoder (v1).

Generates a Z3 harness (`build_model()`) DIRECTLY from static-analysis facts
(domain.abstracter). The LLM no longer invents Solidity semantics; it only
writes the PROPERTY assertion against harness symbols V[...].

Soundness policy (over-approximation — anything untranslatable becomes FREE,
never assumed):
  - Untranslatable guard       -> guard DROPPED (weaker assumption = more states)
  - External call              -> quality PARTIAL; state effects remain havocked
  - Branches                   -> quality PARTIAL; conditions kept as comments
  - Unknown RHS/LHS/tokens     -> affected variable left unconstrained

model_quality:
  FULL    straight-line, no external calls, every guard & assignment encoded
  PARTIAL some encoded, rest soundly havocked (UNSAT still meaningful)
  NONE    encoder failed -> caller falls back to legacy LLM-only mode

Symbol conventions (registry keys -> z3 names):
  'total'          -> total__old      (scalar state, read view)
  'total@new'      -> total__new     (scalar state, post-call value)
  'bal[S]'         -> bal__S         (mapping slot at msg.sender, read view)
  'bal[S]@new'     -> bal__S_new     (mapping slot, write view)
  'arg_amount'     -> a_amount       (function parameter, attacker-controlled)
  'loc_x'          -> l_x            (function-local variable)
"""

import logging
import re

logger = logging.getLogger(__name__)

MODEL_QUALITY_FULL = "FULL"
MODEL_QUALITY_PARTIAL = "PARTIAL"

_IDENT_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_.]*")
_INDEX_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\[([^\[\]]+)\]")


def _san(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", name)


def _translate(expr: str, valid_names: set[str]) -> tuple[str | None, list[str]]:
    """Final textual normalization into Z3-python; returns (code, leftovers)."""
    e = " ".join(expr.split())
    e = e.replace("&&", " and ").replace("||", " or ")
    e = re.sub(r"(?<![!<>=])!(?!=)", " not ", e)
    e = re.sub(r"\b(\d+)e(\d+)\b", r"(\1 * 10**\2)", e)

    leftovers = []
    for tok in _IDENT_RE.findall(e):
        base = tok.split(".", 1)[0]
        if base not in valid_names:
            leftovers.append(tok)
    if "(" in e or "[" in e:
        leftovers.extend(re.findall(r"\w+\s*[(\[]", e))
    if leftovers:
        return None, sorted(set(leftovers))
    return e, []


PROPERTY_PROTOCOL_COMMENT = """
# ==== YOUR TASK: write the verification property ONLY ====
# Protocol (mandatory):
#   1. Call:  solver, V = build_model()
#   2. Assert the NEGATION of the invariant you want to disprove, using ONLY
#      symbols from V (e.g. V['total@new'], V['arg_amount'], V['bal[S]@new']):
#         solver.add(Not(<property expression over V symbols>))
#   3. Finish with EXACTLY one of:
#         if solver.check() == sat:
#             print("BUG FOUND:", solver.model())
#         else:
#             print("Property holds")
# Do NOT redefine state variables, guards, or transitions. The model above was
# generated from static analysis and is authoritative.
"""


class HarnessEncoder:
    def __init__(self, analysis: dict):
        self.analysis = analysis
        self.contract = analysis.get("contract", "")
        self.state_vars = {v["name"] for v in analysis.get("storage_layout", [])}
        self.decls: list[str] = []
        self.bounds: list[str] = []
        self.registry: dict[str, str] = {}  # friendly key -> z3 name

    # ------------------------------------------------------------- symbols
    def _reg(self, friendly: str, zname: str, bounded: bool = True) -> str:
        if friendly not in self.registry:
            self.registry[friendly] = zname
            self.decls.append(f"{zname} = Int('{zname}')")
            if bounded:
                self.bounds.append(f"{zname} >= 0")
        return self.registry[friendly]

    def _scalar_pair(self, name: str):
        self._reg(name, f"{_san(name)}__old")
        return self._reg(f"{name}@new", f"{_san(name)}__new")

    def _slot_pair(self, base: str, idx_key: str):
        zn = f"{_san(base)}__{idx_key}"
        self._reg(f"{base}[{idx_key}]", zn)
        return self._reg(f"{base}[{idx_key}]@new", zn + "_new")

    # -------------------------------------------------------- substitution
    def _prep(self, text: str) -> str:
        text = (text.replace("msg.sender", "msg_sender")
                    .replace("block.timestamp", "block_timestamp")
                    .replace("msg.value", "msg_value"))
        return text

    def _read_view(self, text: str, params: dict) -> str:
        """Substitutes identifiers with their READ-side (old) z3 symbols."""
        text = self._prep(text)

        def idx_repl(m):
            base, raw_idx = m.group(1), m.group(2).strip()
            if base not in self.state_vars:
                return m.group(0)
            ik = "S" if raw_idx == "msg_sender" else _san(raw_idx)[:18] or "x"
            return self._slot_pair(base, ik)  # old symbol

        text = _INDEX_RE.sub(idx_repl, text)
        for friendly, z in self.registry.items():
            if "@" in friendly or "[" in friendly:
                continue
            text = re.sub(rf"\b{re.escape(friendly)}\b(?!\[)", z, text)
        for pname, z in params.items():
            text = re.sub(rf"\b{re.escape(pname)}\b(?!\[)", z, text)
        return text

    def _lhs_target(self, lhs: str, params: dict) -> tuple[str, str, str | None]:
        """Resolves an assignment LHS to (target_zname, current_value_expr, kind).
        kind ∈ {'scalar_state', 'slot_state', 'local'}."""
        lhs = self._prep(lhs.strip())
        m = _INDEX_RE.match(lhs)
        if m and m.group(1) in self.state_vars:
            base, raw_idx = m.group(1), m.group(2).strip()
            ik = "S" if raw_idx == "msg_sender" else _san(raw_idx)[:18] or "x"
            self._slot_pair(base, ik)                      # ensures both registered
            cur = self.registry[f"{base}[{ik}]"]
            new_sym = self.registry[f"{base}[{ik}]@new"]
            return new_sym, cur, "slot_state"
        if lhs in self.state_vars:
            new_sym = self._scalar_pair(lhs)
            cur = self.registry[lhs]
            return new_sym, cur, "scalar_state"
        zl = self._reg(f"loc_{lhs}", f"l_{_san(lhs)}", bounded=False)
        return zl, zl, "local"

    # -------------------------------------------------------------- encode
    def encode_function(self, focus_function: str) -> dict | None:
        functions = self.analysis.get("functions", {})
        key = next((k for k in functions
                    if k.split("(", 1)[0] == focus_function.split("(", 1)[0]), None)
        if key is None:
            return None
        f = functions[key]

        quality = MODEL_QUALITY_FULL
        untranslated: list[str] = []

        # ---- parameters (attacker-controlled) ----
        params: dict[str, str] = {}
        for p in f.get("params", []):
            if p["type"].startswith("uint") or p["type"] in ("address",):
                params[p["name"]] = self._reg(f"arg_{p['name']}",
                                              f"a_{_san(p['name'])}")
            else:
                untranslated.append(f"param not modeled: {p['name']}:{p['type']}")
                quality = MODEL_QUALITY_PARTIAL

        # ---- ambient ----
        self._reg("msg_sender", "msg_sender")
        self._reg("msg_value", "msg_value")
        self._reg("block_timestamp", "block_timestamp")
        self._reg("address_this", "address_this", bounded=False)

        # ---- ALL storage variables registered upfront (old/new pairs) so
        # invariants and guards can reference state this function never
        # touches; untouched vars stay unconstrained unless constrained above.
        for sv in sorted(self.state_vars):
            self._scalar_pair(sv)

        valid_names = set(self.registry.values())

        def finalize(text: str, what: str):
            """Read-substitute then validate; returns code or None (sound drop)."""
            sub = self._read_view(text, params)
            code, left = _translate(sub, set(self.registry.values()))
            if code is None:
                nonlocal quality
                quality = MODEL_QUALITY_PARTIAL
                untranslated.append(f"{what} dropped/unmodeled: {text}")
                return None
            return code

        # ---- guards ----
        guard_codes = []
        for g in f.get("guards", []):
            text = g["text"] if isinstance(g, dict) else g
            code = finalize(text, "guard")
            if code is not None:
                guard_codes.append(code)

        # ---- assignments ----
        trans_codes = []
        assigns = f.get("assignments", [])
        ext_order = f.get("first_external_call_order")
        for a in assigns:
            op, lhs, rhs, order = a["op"], a["lhs"], a["rhs"], a["order"]
            if ext_order is not None and order >= ext_order:
                quality = MODEL_QUALITY_PARTIAL
                untranslated.append(
                    f"external call at event {ext_order}: post-call write "
                    f"'{lhs} {op} {rhs}' havocked (reentrancy may alter it)")
                continue
            target, cur, kind = self._lhs_target(lhs, params)
            rhs_code = finalize(rhs, f"rhs of '{lhs}'")
            if rhs_code is None:
                continue
            if kind == "local":
                trans_codes.append(f"{target} == ({rhs_code})")
            elif op == "=":
                trans_codes.append(f"{target} == ({rhs_code})")
            else:
                op_core = op[0]
                trans_codes.append(f"{target} == (({cur}) {op_core} ({rhs_code}))")

        if f.get("has_branch"):
            quality = MODEL_QUALITY_PARTIAL
            for c in f.get("branch_conditions_src", []):
                untranslated.append(f"branch condition kept as comment only: {c}")

        if f.get("has_external_call") and quality == MODEL_QUALITY_FULL:
            quality = MODEL_QUALITY_PARTIAL

        # ---- assemble ----
        lines = [
            "# ==== DETERMINISTIC SEMANTIC MODEL (generated by domain/semantics.py) ====",
            f"# contract={self.contract} function={key} quality={quality}",
            "# Soundness: unmodeled behavior is UNCONSTRAINED (over-approximation).",
            "from z3 import *",
            "",
            "def build_model():",
        ]
        lines.extend(f"    {d}" for d in self.decls)
        lines.append("    _bounds = [" + ", ".join(self.bounds) + "]")
        lines.append("    _guards = [" + ", ".join(guard_codes) + "]")
        lines.append("    _transitions = [" + ", ".join(trans_codes) + "]")
        lines.append("    solver = Solver()")
        lines.append("    solver.add(_bounds + _guards + _transitions)")
        # Map friendly keys to the ACTUAL z3 Int objects (not their names).
        v_items = ", ".join(f"{k!r}: {z}" for k, z in self.registry.items())
        lines.append("    V = {" + v_items + "}")
        lines.append("    return solver, V")

        return {
            "function": key,
            "contract": self.contract,
            "quality": quality,
            "code": "\n".join(lines),
            "untranslated": untranslated[:20],
            "assumptions": [
                "uint256 modeled as unbounded Int: overflow wraparound is NOT "
                "simulated (values above 2**256-1 stay reachable in-model)",
                "soundness direction: unbounded Int OVER-approximates uint256, "
                "so UNSAT verdicts remain valid proofs; SAT coverage is "
                "asymmetric — wrap-induced counterexamples at the 2**256 "
                "boundary can be missed and need an explicit BitVec pass",
                "integer division truncation exact only for non-negative operands",
                "mapping slots modeled per concrete index seen in source",
            ],
            "symbols": dict(self.registry),
        }


def generate_harness(analysis: dict | None, focus_function: str) -> dict | None:
    """Public entry: returns harness dict or None (caller falls back)."""
    if not analysis:
        return None
    try:
        return HarnessEncoder(analysis).encode_function(focus_function)
    except Exception as e:  # never let encoding kill an audit
        logger.warning("[SEMANTICS] harness generation failed for %s (non-fatal): %s",
                       focus_function, e)
        return None


def compose_script(harness: dict, property_code: str) -> str:
    """Combines the deterministic model with the LLM-authored property block."""
    return harness["code"] + "\n" + PROPERTY_PROTOCOL_COMMENT + "\n" + property_code.strip() + "\n"
