import os
import logging
from pathlib import Path


def _env_int(name, default):
    value = os.environ.get(name)
    return int(value) if value and value.isdigit() else default


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

# Default contracts folder for local runs (always overridable via --contracts / env)
CONTRACTS_FOLDER = os.environ.get("GODEL_CONTRACTS_FOLDER", "FolderName")

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

# ==========================================
# TIMEOUTS
# ==========================================
PER_FUNCTION_TIMEOUT = _env_float("GODEL_PER_FUNCTION_TIMEOUT", 600.0)
MAX_WORKERS          = _env_int("GODEL_MAX_WORKERS", 2)

# ==========================================
# LLM RETRY
# ==========================================
LLM_RETRY_ATTEMPTS = _env_int("GODEL_LLM_RETRY_ATTEMPTS", 3)
LLM_RETRY_BACKOFF  = _env_float("GODEL_LLM_RETRY_BACKOFF", 2.0)


def is_dry_run() -> bool:
    return os.environ.get("GODEL_DRY_RUN", "0") in ("1", "true", "True")


def setup_logging(level: str = None):
    level = level or os.environ.get("GODEL_LOG_LEVEL", "INFO")
    logging.basicConfig(
        level=getattr(logging, str(level).upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
