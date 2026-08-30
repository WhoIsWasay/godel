import ast
import os
import sys
import subprocess
import tempfile

from domain import config

# Explicit sentinels the generated scripts MUST print (see
# prompts/property_generator_prompt.txt). A clean exit without a sentinel is
# INCONCLUSIVE, never "sat" (C2 fix: no more default-to-vulnerability).
SAT_SENTINEL = "BUG FOUND:"
UNSAT_SENTINEL = "Property holds"

# Vacuity defense: every property script must first check that its BASE model
# (bounds + preconditions, WITHOUT the violation condition) is satisfiable.
# If the base model is over-constrained, every later check is vacuously UNSAT
# and any "safe" verdict is a FALSE NEGATIVE — the exact failure class that
# missed the PoolTogether H-05 finding. The probe is machine-checked here.
SANITY_SAT = "SANITY: sat"
SANITY_UNSAT = "SANITY: unsat"


def _classify_sentinels(output: str) -> tuple[str, str | None]:
    """Maps a script's stdout to (status, error). Pure function — unit tested.

    Priority: a failed SANITY probe poisons the whole run regardless of later
    sentinels, because every subsequent check was run against an impossible
    model. Then the normal unambiguous-verdict rules apply."""
    if SANITY_UNSAT in output:
        return "vacuous", (
            "SANITY probe returned unsat: the base model (bounds + "
            "preconditions) is over-constrained and unreachable. Every check "
            "was vacuously UNSAT — this is NOT a safety proof. Relax or "
            "remove the contradictory precondition(s) and regenerate."
        )
    has_sat = SAT_SENTINEL in output
    has_unsat = UNSAT_SENTINEL in output
    if has_sat and not has_unsat:
        return "sat", None
    if has_unsat and not has_sat:
        return "unsat", None
    # Ambiguous output (both sentinels, or neither — e.g. truncated
    # generation or early return). Never guess a verdict.
    return "inconclusive", (
        f"Script exited cleanly but did not print an unambiguous "
        f"verdict sentinel (expected exactly one of "
        f"{SAT_SENTINEL!r} / {UNSAT_SENTINEL!r})."
    )


def _lint_property_quality(z3_code: str) -> str | None:
    """Structural quality gate for LLM-generated property scripts. Returns
    None when the script can plausibly produce a real verdict, else a
    rejection reason fed back to the specifier for repair.

    Prevents the two degenerate property classes deterministically:
    - LOOSE scripts (no check / no add) can never produce a verdict.
    - Scripts without a SANITY probe can silently report vacuous UNSATs."""
    tree = ast.parse(z3_code)

    has_add = False
    has_check = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "add":
                has_add = True
            elif node.func.attr == "check":
                has_check = True

    if not has_add:
        return ("Quality gate: script contains no solver.add(...) constraints — "
                "an empty model proves nothing. Encode the function's state bounds "
                "and the negated property.")
    if not has_check:
        return ("Quality gate: script never calls solver.check() — no verdict can "
                "be produced. Add a check for the negated property.")
    if "SANITY:" not in z3_code:
        return ("Quality gate: script has no SANITY probe. Before asserting the "
                "violation, you MUST check the base model alone: "
                "s.push(); print('SANITY:', s.check()); s.pop(). "
                "Without it, an over-constrained model yields a vacuous UNSAT "
                "that masquerades as a safety proof.")
    return None


# --- Safety gate -----------------------------------------------------------
# Generated scripts are executed with the interpreter, so a prompt-injected or
# hallucinating LLM could otherwise run arbitrary code on the host. Scripts
# only ever need `from z3 import *` plus pure computation, so anything on the
# lists below is rejected BEFORE execution (status "error" -> the CEGIS repair
# loop regenerates the property with the rejection reason as feedback).
_FORBIDDEN_MODULES = {
    "os", "sys", "subprocess", "socket", "shutil", "ctypes", "importlib",
    "requests", "urllib", "http", "ftplib", "telnetlib", "webbrowser",
    "multiprocessing", "signal", "pathlib", "tempfile", "pickle", "io",
}
_FORBIDDEN_CALLS = {"eval", "exec", "compile", "open", "__import__",
                    "input", "breakpoint", "globals", "locals"}
_ALLOWED_DUNDERS = {"__name__"}  # benign in generated boilerplate


def validate_script(z3_code: str):
    """AST-level safety gate. Returns None when the script is clean, else a
    human-readable rejection reason (fed back to the specifier for repair)."""
    try:
        tree = ast.parse(z3_code)
    except SyntaxError as e:
        return f"SyntaxError: {e}"

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in _FORBIDDEN_MODULES:
                    return f"forbidden import '{alias.name}'"
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root and root in _FORBIDDEN_MODULES:
                return f"forbidden import from '{node.module}'"
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in _FORBIDDEN_CALLS:
                return f"forbidden call '{node.func.id}()'"
        elif isinstance(node, ast.Name):
            if (node.id.startswith("__") and node.id.endswith("__")
                    and node.id not in _ALLOWED_DUNDERS):
                return f"forbidden dunder reference '{node.id}'"
        elif isinstance(node, ast.Attribute):
            if node.attr.startswith("__") and node.attr.endswith("__"):
                return f"forbidden dunder attribute access '.{node.attr}'"
    return None


def _unlink_quietly(path: str) -> None:
    """Best-effort temp-file removal. On Windows the just-killed z3 child can
    still hold the file for a moment after a timeout; an unguarded os.unlink
    in `finally` would replace the carefully built timeout/error result with
    a raw PermissionError. Retry once briefly, then give up — a stray temp
    script is harmless, a lost verdict is not."""
    import time as _time
    for attempt in range(3):
        try:
            os.unlink(path)
            return
        except OSError:
            if attempt < 2:
                _time.sleep(0.2)


def run_z3(z3_code: str, strict: bool = False) -> dict:
    violation = validate_script(z3_code)
    if violation:
        return {"status": "error", "output": None,
                "error": f"Safety gate rejected script: {violation}",
                "z3_code": z3_code}

    # Strict mode applies to LLM-generated property scripts only (harness and
    # vacuity-probe scripts are generated by trusted code and skip the lint).
    if strict:
        quality_issue = _lint_property_quality(z3_code)
        if quality_issue:
            return {"status": "error", "output": None,
                    "error": quality_issue, "z3_code": z3_code}

    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(z3_code)
        temp_path = f.name

    try:
        result = subprocess.run(
            [sys.executable, temp_path],
            capture_output=True,
            text=True,
            timeout=config.Z3_TIMEOUT_SECONDS,
            cwd=os.path.dirname(temp_path)
        )
        if result.returncode == 0:
            output = result.stdout.strip()
            status, error = _classify_sentinels(output)
            return {"status": status,
                    "output": output if status in ("sat", "unsat") else None,
                    "error": error, "z3_code": z3_code}
        else:
            return {"status": "error", "output": None, "error": result.stderr, "z3_code": z3_code}
    except subprocess.TimeoutExpired:
        return {"status": "error", "output": None,
                "error": f"Z3 timeout ({config.Z3_TIMEOUT_SECONDS}s)", "z3_code": z3_code}
    except Exception as e:
        return {"status": "error", "output": None, "error": str(e), "z3_code": z3_code}
    finally:
        _unlink_quietly(temp_path)
