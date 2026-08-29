import os
import shutil
import logging
from pathlib import Path


def _env_int(name, default):
    value = os.environ.get(name)
    return int(value) if value and value.isdigit() else default


def find_tool(name: str) -> str:
    """Locate an external binary: PATH first, then well-known install dirs
    (foundryup does NOT add itself to PATH on fresh machines, which made every
    Gatekeeper run degrade to 'tool_missing'). Returns the resolved path, or
    the bare name so subprocess errors stay familiar."""
    found = shutil.which(name)
    if found:
        return found

    suffixes = [name] if os.name != "nt" else [name + ".exe", name]
    search_dirs = [
        Path.home() / ".foundry" / "bin",
        Path("/usr/local/bin"),
        Path("/usr/bin"),
        Path("C:/Program Files/solc"),
    ]
    for d in search_dirs:
        for suf in suffixes:
            candidate = d / suf
            if candidate.is_file():
                return str(candidate)
    return name


# Resolved external tool binaries (fall back to bare name; gatekeeper's
# FileNotFoundError handler still covers a genuinely missing install).
FORGE_BIN = find_tool("forge")
SOLC_BIN = find_tool("solc")


def _env_float(name, default):
    value = os.environ.get(name)
    try:
        return float(value) if value else default
    except ValueError:
        return default


# ==========================================
# PATHS (root-anchored, never CWD-dependent)
# ==========================================
PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROMPTS_DIR = PROJECT_ROOT / "prompts"

# Foundry project root (forge runs here; src/ + test/ live under it)
FOUNDRY_ROOT = Path(os.environ.get("GODEL_FOUNDRY_ROOT", str(PROJECT_ROOT)))

# Output root (overridable so CI can point artifacts somewhere explicit)
OUTPUT_DIR = Path(os.environ.get("GODEL_OUTPUT_DIR", str(PROJECT_ROOT / "output")))

# Default contracts folder for local runs (always overridable via --contracts / env).
# Empty by default so a bare run fails LOUDLY with instructions instead of
# silently auditing nothing (audit fix: "FolderName" placeholder pointed nowhere).
CONTRACTS_FOLDER = os.environ.get("GODEL_CONTRACTS_FOLDER", "")

XML_OUTPUT_FOLDER  = OUTPUT_DIR / "xml"
FINDINGS_FOLDER    = OUTPUT_DIR / "findings"
REPORTS_FOLDER     = OUTPUT_DIR / "reports"
PROOFS_FOLDER      = OUTPUT_DIR / "proofs"
FIXES_FOLDER       = OUTPUT_DIR / "fixes"
SUBMISSIONS_FOLDER = OUTPUT_DIR / "submissions"
DEBUG_FOLDER       = OUTPUT_DIR / "debug_tests"


# ==========================================
# ITERATION / RETRY LIMITS (env-overridable)
# ==========================================
SUPERVISOR_MAX_ITERATIONS = _env_int("GODEL_SUPERVISOR_MAX_ITERATIONS", 3)
EXECUTOR_MAX_ITERATIONS    = _env_int("GODEL_EXECUTOR_MAX_ITERATIONS", 4)
GATEKEEPER_MAX_RETRIES     = _env_int("GODEL_GATEKEEPER_MAX_RETRIES", 3)
HUNTER_MAX_PARSE_RETRIES   = _env_int("GODEL_HUNTER_PARSE_RETRIES", 2)
# Independent isolator passes per function, merged with line/intent dedup.
# Default 1 keeps cost unchanged; 2-3 lifts recall (each pass samples a
# different hypothesis path) at proportional hunter-token cost.
HUNTER_PASSES              = _env_int("GODEL_HUNTER_PASSES", 1)
FUNCTION_MAX_RETRIES       = _env_int("GODEL_FUNCTION_MAX_RETRIES", 2)

# ==========================================
# TIMEOUTS
# ==========================================
PER_FUNCTION_TIMEOUT = _env_float("GODEL_PER_FUNCTION_TIMEOUT", 1200.0)
MAX_WORKERS          = _env_int("GODEL_MAX_WORKERS", 8)
# Cap on simultaneous LLM invokes across all parallel graph threads. A burst
# of 8 concurrent hunter calls once triggered a provider episode of instant
# empty-200 responses; throttling keeps load on the provider bounded.
LLM_CONCURRENCY      = _env_int("GODEL_LLM_CONCURRENCY", 3)

# Opt-in read-only fast path (default OFF so default coverage is unchanged).
# When enabled, functions with no storage writes, no external calls and not
# payable are skipped entirely (they cannot violate the state-transition
# invariants the Z3 harness models). Tradeoff: view/pure logic bugs are no
# longer audited.
SKIP_READONLY_FUNCTIONS = os.environ.get("GODEL_SKIP_READONLY", "0") in ("1", "true", "True")

# Compositional verification phase (default ON): after the per-function graphs
# finish, one fast LLM call proposes contract-wide invariants from STATIC FACTS
# only; Z3 then proves/refutes each across ALL functions locally (no further
# credits). Broken invariants merge into the main results list. Set
# GODEL_DISCOVERY=0 to run the classic per-function audit alone.
RUN_DISCOVERY = os.environ.get("GODEL_DISCOVERY", "1") in ("1", "true", "True")
DISCOVERY_MAX_INVARIANTS = _env_int("GODEL_DISCOVERY_MAX", 4)

# Tool timeouts (previously hardcoded in z3_runner.py / gatekeeper.py)
Z3_TIMEOUT_SECONDS   = _env_float("GODEL_Z3_TIMEOUT", 30.0)
FORGE_TIMEOUT_SECONDS = _env_float("GODEL_FORGE_TIMEOUT", 45.0)

# ==========================================
# LLM RETRY
# ==========================================
LLM_RETRY_ATTEMPTS = _env_int("GODEL_LLM_RETRY_ATTEMPTS", 5)
LLM_RETRY_BACKOFF  = _env_float("GODEL_LLM_RETRY_BACKOFF", 3.0)

# Isolator pass model override. The Isolator runs 3x per contract and is pure
# candidate generation (every proposal is machine-verified downstream), so a
# fast/cheap model is usually sufficient; defaults to the reasoning model when
# unset. Example: GODEL_ISOLATOR_MODEL=deepseek-v4-flash
ISOLATOR_MODEL = os.environ.get("GODEL_ISOLATOR_MODEL", "").strip()


def is_dry_run() -> bool:
    return os.environ.get("GODEL_DRY_RUN", "0") in ("1", "true", "True")


def setup_logging(level: str = None):
    level = level or os.environ.get("GODEL_LOG_LEVEL", "INFO")
    logging.basicConfig(
        level=getattr(logging, str(level).upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
