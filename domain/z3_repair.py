"""domain/z3_repair.py — deterministic, LLM-free repair of generated Z3 scripts.

The specifier's first Z3 draft fails at a high rate (observed on every function
in production runs), and each failure historically cost one full LLM repair
call before CEGIS re-ran the solver. The dominant failure class is a Python
``NameError`` — the model references a symbol it never bound:

  * harness mode: it writes a bare name (``totalSupply``) instead of the
    required ``V['totalSupply']`` lookup;
  * standalone mode: it misspells one of its own ``BitVec`` declarations.

Both are recoverable WITHOUT an LLM round-trip: the runtime error names the
exact undefined identifier, and the correct binding is either (a) a near-match
among the script's own module-scope names, or (b) a near-match among the
harness ``V`` symbol keys. This module performs that substitution so the CEGIS
loop can re-run immediately, reserving LLM repairs for genuinely semantic
failures. It also persists every error/repair so runs are diagnosable instead
of vanishing into stdout.

Repair here is deliberately conservative: it only fires on an explicit
``NameError``, only substitutes when a high-confidence near-match exists, and
never touches quoted string contents (so ``V['x']`` keys are not mangled).
Anything it cannot confidently fix returns ``None`` and the caller falls back
to the existing LLM repair path.
"""
import ast
import builtins
import difflib
import json
import logging
import os
import re
import time

logger = logging.getLogger(__name__)

# NameError: name 'X' is not defined   (stable across CPython 3.x)
_NAME_ERROR_RE = re.compile(r"NameError: name '([^']+)' is not defined")
# Minimum similarity for a substitution to be trusted without an LLM.
_MATCH_CUTOFF = 0.8


# ---------------------------------------------------------------------------
# Introspection
# ---------------------------------------------------------------------------

def extract_missing_name(error: str):
    """Return the undefined identifier from a NameError traceback, else None."""
    if not error:
        return None
    m = _NAME_ERROR_RE.search(error)
    return m.group(1) if m else None


def _collect_arg_names(func_node, names: set):
    args = func_node.args
    for a in (args.posonlyargs + args.args + args.kwonlyargs):
        names.add(a.arg)
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)


def _collect_store_names(node, names: set):
    """Store-context bindings within `node`, WITHOUT descending into nested
    function/class bodies (their locals are not module bindings)."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        names.add(node.name)
        _collect_arg_names(node, names)
        return
    if isinstance(node, ast.ClassDef):
        names.add(node.name)
        return
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store):
            names.add(sub.id)


def module_scope_names(code: str) -> set:
    """Names bound at module scope (the script's real top-level namespace).

    Only module-scope bindings are valid bare references; names bound inside
    ``build_model()`` are locals and must NOT be offered as bare substitutions
    (using them would re-trigger the same NameError)."""
    names = set()
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return names
    for stmt in tree.body:
        _collect_store_names(stmt, names)
    return names


def _import_aliases(tree) -> set:
    """Names brought into scope by import statements (incl. `import a.b` -> a)."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name == "*":
                    continue
                names.add(alias.asname or alias.name.split(".")[0])
    return names


def _function_arg_names(tree) -> set:
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _collect_arg_names(node, names)
        elif isinstance(node, ast.Lambda):
            for a in (node.args.posonlyargs + node.args.args + node.args.kwonlyargs):
                names.add(a.arg)
    return names


def static_undefined_names(code: str) -> set:
    """Names referenced (Load context) but provably unbound in the script,
    excluding builtins and the ``from z3 import *`` namespace. Empty on
    syntax errors (preflight becomes a no-op). Used for the pre-first-run
    fix: catches the dominant NameError class before any execution."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return set()

    bound = set(dir(builtins))
    bound |= module_scope_names(code)
    bound |= _import_aliases(tree)
    bound |= _function_arg_names(tree)
    # Any Store-context name anywhere (function locals are valid references
    # within their own body; coarse but false-positive-free).
    bound |= {n.id for n in ast.walk(tree)
              if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}

    star_z3 = any(
        isinstance(n, ast.ImportFrom) and (n.module or "").split(".")[0] == "z3"
        and any(a.name == "*" for a in n.names)
        for n in ast.walk(tree)
    )
    if star_z3:
        try:
            import z3 as _z3
            bound |= set(dir(_z3))
        except Exception:
            # z3 unavailable for introspection: skip preflight rather than
            # risk false positives on z3 star-imported names.
            return set()

    undefined = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id not in bound:
                undefined.add(node.id)
    return undefined


def preflight_fix(code: str, known_symbols=None) -> str | None:
    """Deterministically fix statically-detectable undefined names BEFORE
    the first execution. Returns corrected code, or None when nothing
    confident can be changed (script runs as-is)."""
    if not code:
        return None
    fixed = code
    changed = False
    for missing in sorted(static_undefined_names(code)):
        local = best_match(missing, module_scope_names(fixed) - {missing})
        if local:
            fixed = _sub_identifier(fixed, missing, local)
            logger.info("[Z3-REPAIR] preflight: %r -> %r (module-scope)",
                        missing, local)
            changed = True
            continue
        if is_harness_mode(fixed):
            vkeys = v_symbol_keys(fixed)
            if known_symbols:
                vkeys |= set(known_symbols)
            key = missing if missing in vkeys else best_match(missing, vkeys)
            if key:
                fixed = _sub_identifier(fixed, missing, f"V[{key!r}]")
                logger.info("[Z3-REPAIR] preflight: %r -> V[%r] (harness)",
                            missing, key)
                changed = True
    return fixed if changed else None


def v_symbol_keys(code: str) -> set:
    """String keys of any ``V = {...}`` dict literal (the harness symbol
    table). Works whether V is built at module scope or inside build_model()."""
    keys = set()
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return keys
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "V":
                    for k in node.value.keys:
                        if isinstance(k, ast.Constant) and isinstance(k.value, str):
                            keys.add(k.value)
    return keys


def is_harness_mode(code: str) -> bool:
    return "def build_model" in (code or "")


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def _norm(s: str) -> str:
    """Case/underscore/punct-insensitive fingerprint for fuzzy comparison."""
    return re.sub(r"[^a-z0-9]", "", s.lower())


def best_match(missing: str, candidates) -> str | None:
    """Highest-confidence candidate for `missing`, or None.

    Order: exact normalized equality, then difflib on normalized fingerprints
    (cutoff _MATCH_CUTOFF). Never returns `missing` itself."""
    cands = [c for c in set(candidates) if c and c != missing]
    if not cands:
        return None
    nm = _norm(missing)
    for c in cands:
        if _norm(c) == nm:
            return c
    norm_map = {}
    for c in cands:
        norm_map.setdefault(_norm(c), c)
    close = difflib.get_close_matches(nm, list(norm_map.keys()), n=1,
                                      cutoff=_MATCH_CUTOFF)
    if close:
        return norm_map[close[0]]
    return None


# ---------------------------------------------------------------------------
# Substitution
# ---------------------------------------------------------------------------

def _sub_identifier(code: str, missing: str, replacement: str) -> str:
    """Replace bare occurrences of `missing` with `replacement`, skipping any
    occurrence adjacent to a quote (so existing ``V['missing']`` string keys
    and literals are left intact)."""
    pat = re.compile(r"(?<!['\"\w])" + re.escape(missing) + r"(?!['\"\w])")
    return pat.sub(replacement.replace("\\", r"\\"), code)


def repair_name_error(code: str, error: str, known_symbols=None) -> str | None:
    """Deterministically fix a NameError in a generated Z3 script.

    Returns the corrected code, or None when no confident fix exists (caller
    should fall back to LLM repair). Strategy:
      1. self-correction — the missing name is a near-match of a module-scope
         binding already in the script (standalone-mode misspelling);
      2. harness lookup — in harness mode, the missing name is a near-match of
         a ``V`` symbol key, rewritten as ``V['key']``.
    """
    missing = extract_missing_name(error)
    if not missing or not code:
        return None

    # 1) Near-match of an already-bound module-scope name.
    local = best_match(missing, module_scope_names(code) - {missing})
    if local:
        fixed = _sub_identifier(code, missing, local)
        if fixed != code:
            logger.info("[Z3-REPAIR] deterministic: %r -> %r (module-scope)",
                        missing, local)
            return fixed

    # 2) Harness-mode V lookup.
    if is_harness_mode(code):
        vkeys = v_symbol_keys(code)
        if known_symbols:
            vkeys |= set(known_symbols)
        # Exact key match is the ideal outcome (bare name wrapped into the
        # V lookup) even though it equals `missing` — unlike strategy 1,
        # the replacement is not identity.
        key = missing if missing in vkeys else best_match(missing, vkeys)
        if key:
            fixed = _sub_identifier(code, missing, f"V[{key!r}]")
            if fixed != code:
                logger.info("[Z3-REPAIR] deterministic: %r -> V[%r] (harness)",
                            missing, key)
                return fixed

    return None


# ---------------------------------------------------------------------------
# Persistence (diagnosability)
# ---------------------------------------------------------------------------

def persist_repair_log(debug_folder, focus_function: str, attempts: list,
                       final_result: dict) -> str | None:
    """Write a JSON artifact describing every error/repair for one executor
    run. Best-effort: a persistence failure must never sink the verdict."""
    try:
        os.makedirs(debug_folder, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", str(focus_function or "unknown"))
        fname = f"z3_repair_{safe}_{int(time.time())}_{os.getpid()}.json"
        path = os.path.join(str(debug_folder), fname)
        payload = {
            "focus_function": focus_function,
            "final_status": final_result.get("status"),
            "repairs_used": final_result.get("repairs_used", 0),
            "attempts": attempts,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        return path
    except OSError as e:
        logger.warning("[Z3-REPAIR] persist failed (non-fatal): %s", e)
        return None
