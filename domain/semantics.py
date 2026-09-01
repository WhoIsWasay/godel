"""domain/semantics.py â€" Phase 2 deterministic semantic encoder (v1).

Generates a Z3 harness (`build_model()`) DIRECTLY from static-analysis facts
(domain.abstracter). The LLM no longer invents Solidity semantics; it only
writes the PROPERTY assertion against harness symbols V[...].

Soundness policy (over-approximation â€" anything untranslatable becomes FREE,
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
MODEL_QUALITY_CHAIN = "CHAIN"

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


def _split_top_level(expr: str, seps: list[str]) -> list[str]:
    """Splits on the first separator match at bracket-depth 0 (multi-char
    separators like '||' win over shorter prefixes)."""
    parts, buf, depth, i = [], "", 0, 0
    n = len(expr)
    while i < n:
        ch = expr[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if depth == 0:
            matched = False
            for sep in sorted(seps, key=len, reverse=True):
                if expr.startswith(sep, i):
                    parts.append(buf)
                    buf = ""
                    i += len(sep)
                    matched = True
                    break
            if not matched:
                buf += ch
                i += 1
        else:
            buf += ch
            i += 1
    parts.append(buf)
    return parts


def _translate_condition(sub_text: str, valid_names: set[str]):
    """Translates a boolean CONDITION into Z3-python. Unlike _translate
    (which rejects all parentheses), supports top-level '||'/'&&' chains of
    comparison atoms — the shape Solidity guards/branch conditions actually
    have. Returns None when anything exotic (function calls etc.) appears,
    so callers can havock soundly."""
    s = re.sub(r"(?<![!<>=])!(?!=)", " not ", " ".join(sub_text.split()))
    neg = False
    while s.startswith("not "):
        neg = not neg
        s = s[4:].strip()

    def atom_code(atom: str):
        code, left = _translate(atom, valid_names)
        return code

    def build(part: str) -> str | None:
        conjuncts = _split_top_level(part, ["&&"])
        codes = [atom_code(c.strip()) for c in conjuncts]
        if any(c is None for c in codes):
            return None
        return codes[0] if len(codes) == 1 else f"And({', '.join(codes)})"

    disj = _split_top_level(s, ["||"])
    built = [build(p.strip()) for p in disj]
    if any(b is None for b in built):
        return None
    expr = built[0] if len(built) == 1 else f"Or({', '.join(built)})"
    return ("Not(" + expr + ")") if neg else expr


class HarnessEncoder:
    def __init__(self, analysis: dict, suffix: str = ""):
        self.analysis = analysis
        self.contract = analysis.get("contract", "")
        self.state_vars = {v["name"] for v in analysis.get("storage_layout", [])}
        self.decls: list[str] = []
        self.bounds: list[str] = []
        self.registry: dict[str, str] = {}  # friendly key -> z3 name
        self.suffix = suffix  # for chain encoding: "_c1", "_c2", etc.

    # ------------------------------------------------------------- symbols
    def _reg(self, friendly: str, zname: str, bounded: bool = True) -> str:
        suffixed_friendly = f"{friendly}{self.suffix}" if self.suffix else friendly
        suffixed_zname = f"{zname}{self.suffix}"
        if suffixed_friendly not in self.registry:
            self.registry[suffixed_friendly] = suffixed_zname
            self.decls.append(f"{suffixed_zname} = Int('{suffixed_zname}')")
            if bounded:
                self.bounds.append(f"{suffixed_zname} >= 0")
                self.bounds.append(f"{suffixed_zname} <= 2**256 - 1")
        return self.registry[suffixed_friendly]

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
        kind âˆˆ {'scalar_state', 'slot_state', 'local'}."""
        lhs = self._prep(lhs.strip())
        m = _INDEX_RE.match(lhs)
        if m and m.group(1) in self.state_vars:
            base, raw_idx = m.group(1), m.group(2).strip()
            ik = "S" if raw_idx == "msg_sender" else _san(raw_idx)[:18] or "x"
            self._slot_pair(base, ik)                      # ensures both registered
            s = self.suffix
            cur = self.registry[f"{base}[{ik}]{s}"]
            new_sym = self.registry[f"{base}[{ik}]@new{s}"]
            return new_sym, cur, "slot_state"
        if lhs in self.state_vars:
            new_sym = self._scalar_pair(lhs)
            cur = self.registry[f"{lhs}{self.suffix}"]
            return new_sym, cur, "scalar_state"
        zl = self._reg(f"loc_{lhs}", f"l_{_san(lhs)}", bounded=False)
        return zl, zl, "local"

    # ------------------------------------------------ external call resolution
    _KNOWN_EXTERNAL = frozenset({
        "transfer", "transferFrom", "approve", "call", "delegatecall",
        "staticcall", "send", "create", "create2", "selfdestruct",
    })

    def _resolve_call_target(self, call_expr: str) -> tuple[str, dict] | None:
        """Attempts to resolve an external call to a same-contract function.
        Returns (full_key, facts) or None. Skips known external patterns and
        targets that themselves have external calls."""
        m = re.match(r"(?:this\.)?(?:\w+\.)?(\w+)\s*\(", call_expr.strip())
        if not m:
            return None
        target_name = m.group(1)
        if target_name.lower() in self._KNOWN_EXTERNAL:
            return None
        functions = self.analysis.get("functions", {})
        target_key = next(
            (k for k in functions if k.split("(", 1)[0] == target_name), None)
        if target_key is None:
            return None
        target_facts = functions[target_key]
        if target_facts.get("has_external_call"):
            return None
        return target_key, target_facts

    def _encode_resolved_target_guards(self, target_facts: dict,
                                        params: dict) -> list[str]:
        """Extracts encodable guard constraints from a resolved call target,
        giving Z3 more information about post-call state preconditions."""
        codes = []
        for g in target_facts.get("guards", []):
            text = g["text"] if isinstance(g, dict) else g
            sub = self._read_view(text, params)
            code, _ = _translate(sub, set(self.registry.values()))
            if code:
                codes.append(code)
        return codes

    # -------------------------------------------------------------- encode
    def _encode_raw(self, focus_function: str) -> dict | None:
        """Core encoding logic returning intermediate data without code assembly.
        Returns dict with guard_codes, trans_codes, quality, untranslated,
        registry, decls, bounds, or None if function not found."""
        functions = self.analysis.get("functions", {})
        key = next((k for k in functions
                    if k.split("(", 1)[0] == focus_function.split("(", 1)[0]), None)
        if key is None:
            return None
        f = functions[key]

        quality = MODEL_QUALITY_FULL
        untranslated: list[str] = []

        params: dict[str, str] = {}
        for p in f.get("params", []):
            if p["type"].startswith("uint") or p["type"] in ("address",):
                params[p["name"]] = self._reg(f"arg_{p['name']}",
                                              f"a_{_san(p['name'])}")
            else:
                untranslated.append(f"param not modeled: {p['name']}:{p['type']}")
                quality = MODEL_QUALITY_PARTIAL

        self._reg("msg_sender", "msg_sender")
        self._reg("msg_value", "msg_value")
        self._reg("block_timestamp", "block_timestamp")
        self._reg("address_this", "address_this", bounded=False)

        st_types = {v["name"]: str(v.get("type", "")) for v in self.analysis.get("storage_layout", [])}
        for sv in sorted(self.state_vars):
            self._scalar_pair(sv)
            if "mapping" in st_types.get(sv, ""):
                zn = f"{_san(sv)}__GEN"
                self._reg(f"{sv}[#]", zn)
                self._reg(f"{sv}[#]@new", zn + "_new")

        valid_names = set(self.registry.values())

        def finalize(text: str, what: str):
            sub = self._read_view(text, params)
            code, left = _translate(sub, set(self.registry.values()))
            if code is None:
                nonlocal quality
                quality = MODEL_QUALITY_PARTIAL
                untranslated.append(f"{what} dropped/unmodeled: {text}")
                return None
            return code

        def finalize_cond(text: str) -> str | None:
            try:
                sub = self._read_view(text, params)
                return _translate_condition(sub, set(self.registry.values()))
            except Exception:
                return None

        def _z3_not(code: str) -> str:
            s = code.strip()
            neg = False
            while s.startswith("not "):
                neg = not neg
                s = s[4:].strip()
            return ("Not(" + s + ")") if neg else s

        def _wrap_when(when, params_ref, fin):
            if not when:
                return []
            codes = []
            for w in when:
                if w.get("loop"):
                    return None
                c = fin(w["c"]) if fin is not None else None
                if c is None:
                    return None
                codes.append(_z3_not(c))
            return codes

        guard_codes = []
        for g in f.get("guards", []):
            text = g["text"] if isinstance(g, dict) else g
            when = g.get("when", []) if isinstance(g, dict) else []
            code = finalize(text, "guard")
            if code is None:
                continue
            wrapped = _wrap_when(when, params, finalize_cond)
            if wrapped is None:
                quality = MODEL_QUALITY_PARTIAL
                untranslated.append(f"guard dropped (unencodable branch/loop context): {text}")
                continue
            guard_codes.append(
                f"Implies(And({', '.join(wrapped)}), ({code}))" if wrapped else code)

        trans_codes = []
        written_pairs = []
        success_ctx = []
        any_unconditional_write = False
        assigns = f.get("assignments", [])
        ext_order = f.get("first_external_call_order")
        for a in assigns:
            op, lhs, rhs, order = a["op"], a["lhs"], a["rhs"], a["order"]
            when = a.get("when", [])
            if ext_order is not None and order >= ext_order:
                target, cur, kind = self._lhs_target(lhs, params)
                if kind in ("scalar_state", "slot_state"):
                    written_pairs.append((target, cur))
                resolved = None
                for call_expr in f.get("external_calls", []):
                    resolved = self._resolve_call_target(call_expr)
                    if resolved:
                        break
                if resolved:
                    _tkey, tfacts = resolved
                    t_guards = self._encode_resolved_target_guards(tfacts, params)
                    for tg in t_guards:
                        guard_codes.append(tg)
                    quality = MODEL_QUALITY_PARTIAL
                    untranslated.append(
                        f"external call resolved to {_tkey}: target guards "
                        f"injected; post-call write '{lhs}' partially constrained")
                else:
                    quality = MODEL_QUALITY_PARTIAL
                    untranslated.append(
                        f"external call at event {ext_order}: post-call write "
                        f"'{lhs} {op} {rhs}' havocked (reentrancy may alter it)")
                continue
            wrapped = _wrap_when(when, params, finalize_cond)
            if wrapped is None:
                quality = MODEL_QUALITY_PARTIAL
                untranslated.append(
                    f"write havocked (loop/unencodable branch context): '{lhs} {op} {rhs}'")
                target, cur, kind = self._lhs_target(lhs, params)
                if kind in ("scalar_state", "slot_state"):
                    written_pairs.append((target, cur))
                continue
            target, cur, kind = self._lhs_target(lhs, params)
            if kind in ("scalar_state", "slot_state"):
                written_pairs.append((target, cur))
                if wrapped:
                    key_ctx = tuple(sorted(wrapped))
                    if key_ctx not in {tuple(sorted(s)) for s in success_ctx}:
                        success_ctx.append(list(wrapped))
                else:
                    any_unconditional_write = True
            rhs_code = finalize(rhs, f"rhs of '{lhs}'")
            if rhs_code is None:
                continue
            if kind == "local" or op == "=":
                eq = f"{target} == ({rhs_code})"
            else:
                op_core = op[0]
                eq = f"{target} == (({cur}) {op_core} ({rhs_code}))"
            trans_codes.append(f"Implies(And({', '.join(wrapped)}), {eq})"
                               if wrapped else eq)

        if (written_pairs and success_ctx and not any_unconditional_write):
            R = "Or(" + ", ".join(
                (c[0] if len(c) == 1 else "And(" + ", ".join(c) + ")")
                for c in success_ctx) + ")"
            for new_z, old_z in sorted(set(written_pairs)):
                trans_codes.append(f"Implies(Not({R}), {new_z} == {old_z})")

        if f.get("loops"):
            quality = MODEL_QUALITY_PARTIAL
            untranslated.append("function contains loops — iteration semantics not modeled")

        if f.get("has_external_call") and quality == MODEL_QUALITY_FULL:
            quality = MODEL_QUALITY_PARTIAL

        # A loc_* symbol is UNBOUND when no emitted equality constrains it:
        # havocked writes (loop / unencodable branch context) still register
        # the symbol, leaving the variable free. Asserting a violation on a
        # free variable is trivially SAT — a vacuous "proof". The strict lint
        # in z3_runner uses this list to reject such scripts before execution.
        emitted = "\n".join(guard_codes + trans_codes)
        unbound_locals = [
            friendly for friendly, z in self.registry.items()
            if friendly.startswith("loc_")
            and not re.search(rf"(?<!\w){re.escape(z)}\s*==", emitted)
        ]

        return {
            "function_key": key,
            "guard_codes": guard_codes,
            "trans_codes": trans_codes,
            "quality": quality,
            "untranslated": untranslated[:20],
            "unbound_locals": sorted(unbound_locals),
            "registry": dict(self.registry),
            "decls": list(self.decls),
            "bounds": list(self.bounds),
        }

    def encode_function(self, focus_function: str) -> dict | None:
        """Encodes a single function's state transition as a Z3 harness."""
        raw = self._encode_raw(focus_function)
        if raw is None:
            return None

        lines = [
            "# ==== DETERMINISTIC SEMANTIC MODEL (generated by domain/semantics.py) ====",
            f"# contract={self.contract} function={raw['function_key']} quality={raw['quality']}",
            "# Soundness: unmodeled behavior is UNCONSTRAINED (over-approximation).",
            "from z3 import *",
            "",
            "def build_model():",
        ]
        lines.extend(f"    {d}" for d in raw["decls"])
        lines.append("    _bounds = [" + ", ".join(raw["bounds"]) + "]")
        lines.append("    _guards = [" + ", ".join(raw["guard_codes"]) + "]")
        lines.append("    _transitions = [" + ", ".join(raw["trans_codes"]) + "]")
        lines.append("    # Havocked locals: NO defining equality was emitted for these.")
        lines.append("    # Asserting on them yields vacuous SAT - the strict lint rejects that.")
        lines.append("    _unbound_locals = [" + ", ".join(repr(k) for k in raw["unbound_locals"]) + "]")
        lines.append("    solver = Solver()")
        lines.append("    solver.add(_bounds + _guards + _transitions)")
        v_items = ", ".join(f"{k!r}: {z}" for k, z in raw["registry"].items())
        lines.append("    V = {" + v_items + "}")
        lines.append("    return solver, V")

        return {
            "function": raw["function_key"],
            "contract": self.contract,
            "quality": raw["quality"],
            "code": "\n".join(lines),
            "untranslated": raw["untranslated"],
            "unbound_locals": raw["unbound_locals"],
            "assumptions": [
                "uint256 modeled as bounded Int [0, 2**256-1]: individual "
                "variables are capped, so Z3 can detect when arithmetic results "
                "exceed the uint256 maximum (overflow bugs); modular wraparound "
                "is NOT simulated -- use BitVec(256) wrap-probe for exact wrap semantics",
                "soundness direction: bounded Int stays an OVER-approximation of "
                "uint256 (intermediate arithmetic is unbounded), so UNSAT verdicts "
                "remain valid proofs; SAT now also catches overflow at the boundary",
                "integer division truncation exact only for non-negative operands",
                "mapping slots modeled per concrete index seen in source",
                "symbols listed in _unbound_locals are HAVOCKED (free): any "
                "assertion on them proves nothing and is rejected by the strict "
                "lint -- express violations via bound symbols or inline arithmetic",
            ],
            "symbols": raw["registry"],
        }

    def encode_function_sequence(self, function_names: list[str]) -> dict | None:
        """Models an ordered sequence of function calls as a chained state
        transition. Creates per-call variables (suffixed _c1, _c2, ...) with
        bridge constraints: Call_N new_state == Call_N+1 old_state.

        Returns a chain harness dict with quality CHAIN, or None on failure.
        Soundness: same over-approximation policy as encode_function.
        """
        if len(function_names) < 2:
            return None

        all_decls: list[str] = []
        all_bounds: list[str] = []
        all_guards: list[str] = []
        all_transitions: list[str] = []
        merged_registry: dict[str, str] = {}
        quality = MODEL_QUALITY_CHAIN
        untranslated: list[str] = []
        all_unbound: list[str] = []
        prev_new_map: dict[str, str] = {}  # base_var -> z3_new_name

        for call_idx, fn_name in enumerate(function_names, 1):
            sub = HarnessEncoder(self.analysis, suffix=f"_c{call_idx}")
            raw = sub._encode_raw(fn_name)
            if raw is None:
                untranslated.append(f"function {fn_name} could not be encoded")
                continue

            all_decls.extend(raw["decls"])
            all_bounds.extend(raw["bounds"])
            all_guards.extend(raw["guard_codes"])
            all_transitions.extend(raw["trans_codes"])
            all_unbound.extend(raw.get("unbound_locals", []))

            if call_idx > 1 and prev_new_map:
                for sv in sorted(self.state_vars):
                    new_key = f"{sv}@new_c{call_idx - 1}"
                    old_key = f"{sv}_c{call_idx}"
                    new_z = prev_new_map.get(new_key)
                    old_z = raw["registry"].get(old_key)
                    if new_z and old_z:
                        all_transitions.append(f"{new_z} == {old_z}")

            for sv in sorted(self.state_vars):
                new_key_suf = f"{sv}@new_c{call_idx}"
                new_z = raw["registry"].get(new_key_suf)
                if new_z:
                    prev_new_map[new_key_suf] = new_z

            merged_registry.update(raw["registry"])
            if raw["quality"] == MODEL_QUALITY_PARTIAL:
                untranslated.extend(raw["untranslated"][:5])

        if not all_decls:
            return None

        lines = [
            "# ==== CHAIN DETERMINISTIC SEMANTIC MODEL ====",
            f"# contract={self.contract} sequence={'->'.join(function_names)} quality={quality}",
            "# Soundness: unmodeled behavior is UNCONSTRAINED (over-approximation).",
            "# Bridge: Call_N post-state == Call_N+1 pre-state for all storage.",
            "from z3 import *",
            "",
            "def build_model():",
        ]
        lines.extend(f"    {d}" for d in all_decls)
        lines.append("    _bounds = [" + ", ".join(all_bounds) + "]")
        lines.append("    _guards = [" + ", ".join(all_guards) + "]")
        lines.append("    _transitions = [" + ", ".join(all_transitions) + "]")
        lines.append("    # Havocked locals: NO defining equality was emitted for these.")
        lines.append("    # Asserting on them yields vacuous SAT - the strict lint rejects that.")
        lines.append("    _unbound_locals = [" + ", ".join(repr(k) for k in sorted(set(all_unbound))) + "]")
        lines.append("    solver = Solver()")
        lines.append("    solver.add(_bounds + _guards + _transitions)")
        v_items = ", ".join(f"{k!r}: {z}" for k, z in merged_registry.items())
        lines.append("    V = {" + v_items + "}")
        lines.append("    return solver, V")

        return {
            "function": "->".join(function_names),
            "contract": self.contract,
            "quality": quality,
            "code": "\n".join(lines),
            "untranslated": untranslated[:20],
            "unbound_locals": sorted(set(all_unbound)),
            "assumptions": [
                "chain model: post-state of each call bridged to pre-state of next",
                "each call independently over-approximates (PARTIAL quality possible)",
                "uint256 modeled as bounded Int [0, 2**256-1]",
                "external calls havocked per-call (reentrancy not modeled across chain)",
                "symbols listed in _unbound_locals are HAVOCKED (free): any "
                "assertion on them proves nothing and is rejected by the strict lint",
            ],
            "symbols": merged_registry,
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


def compose_reachability_script(harness: dict) -> str:
    """Build a Z3 script that checks satisfiability of the harness model
    (bounds + guards + transitions) without any property assertion.

    SAT   = the model admits at least one valid execution (pre-state reachable)
    UNSAT = the model is internally inconsistent (guards contradict bounds, or
            transitions contradict guards) — any property trivially holds

    Used by the executor node after a property UNSAT to distinguish genuine
    proofs from vacuous ones."""
    code = harness["code"]
    return code + "\n" + (
        "# === Vacuity probe: is the model satisfiable without any property? ===\n"
        "solver_vac, V_vac = build_model()\n"
        "if solver_vac.check() == sat:\n"
        "    print(\"Property holds\")\n"
        "else:\n"
        "    print(\"BUG FOUND: model is vacuously unsatisfiable\")\n"
    )


def compose_script(harness: dict, property_code: str) -> str:
    """Combines the deterministic model with the LLM-authored property block."""
    return harness["code"] + "\n" + PROPERTY_PROTOCOL_COMMENT + "\n" + property_code.strip() + "\n"
