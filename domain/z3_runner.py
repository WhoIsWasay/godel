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


def run_z3(z3_code: str) -> dict:
    violation = validate_script(z3_code)
    if violation:
        return {"status": "error", "output": None,
                "error": f"Safety gate rejected script: {violation}",
                "z3_code": z3_code}

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
            has_sat = SAT_SENTINEL in output
            has_unsat = UNSAT_SENTINEL in output

            if has_sat and not has_unsat:
                status = "sat"
                error = None
            elif has_unsat and not has_sat:
                status = "unsat"
                error = None
            else:
                # Ambiguous output (both sentinels, or neither — e.g. truncated
                # generation or early return). Never guess a verdict.
                status = "inconclusive"
                error = (
                    f"Script exited cleanly but did not print an unambiguous "
                    f"verdict sentinel (expected exactly one of "
                    f"{SAT_SENTINEL!r} / {UNSAT_SENTINEL!r})."
                )
            return {"status": status, "output": output if status != "inconclusive" else None,
                    "error": error, "z3_code": z3_code}
        else:
            return {"status": "error", "output": None, "error": result.stderr, "z3_code": z3_code}
    except subprocess.TimeoutExpired:
        return {"status": "error", "output": None,
                "error": f"Z3 timeout ({config.Z3_TIMEOUT_SECONDS}s)", "z3_code": z3_code}
    except Exception as e:
        return {"status": "error", "output": None, "error": str(e), "z3_code": z3_code}
    finally:
        os.unlink(temp_path)
