import os
import sys
import subprocess
import tempfile


def run_z3(z3_code: str) -> dict:
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(z3_code)
        temp_path = f.name

    try:
        result = subprocess.run(
            [sys.executable, temp_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            output = result.stdout.strip()
            status = "unsat" if "Property holds" in output else "sat"
            return {"status": status, "output": output, "error": None, "z3_code": z3_code}
        else:
            return {"status": "error", "output": None, "error": result.stderr, "z3_code": z3_code}
    except subprocess.TimeoutExpired:
        return {"status": "error", "output": None, "error": "Z3 timeout", "z3_code": z3_code}
    except Exception as e:
        return {"status": "error", "output": None, "error": str(e), "z3_code": z3_code}
    finally:
        os.unlink(temp_path)