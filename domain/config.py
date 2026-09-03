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
# Grace window granted to graphs still running when the batch timeout fires.
# Threads that outlive the deadline are usually one LLM round from saving a
# verified finding; counting them dead immediately split-brained the report
# (SUMMARY said 2 findings while 3 landed on disk — CI run 33307904841).
BATCH_TIMEOUT_GRACE  = _env_float("GODEL_BATCH_TIMEOUT_GRACE", 300.0)
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

# MCP keep-alive heartbeat. A re-confirm/full audit runs Z3 (<=Z3_TIMEOUT) +
# Foundry (<=FORGE_TIMEOUT) + several LLM calls — often minutes. The MCP stdio
# transport captured sys.stdout at startup, and MCP clients apply a request/
# idle timeout (SDK default ~60s): a silent channel makes them abort the call
# mid-run ("MCP tool timed out") after credits were already spent. While the
# tool runs the server emits a notification every MCP_HEARTBEAT_SECONDS so the
# channel always shows activity — report_progress for clients that pass a
# progressToken, plus a token-independent logging notification for all others.
# Set to 0 to disable.
MCP_HEARTBEAT_SECONDS = _env_float("GODEL_MCP_HEARTBEAT_SECONDS", 5.0)

# ==========================================
# Z3 WITNESS MINIMIZATION (groundability)
# ==========================================
# Z3 models uint256 as a bounded Int [0, 2**256-1] and does NOT minimize, so a
# SAT witness can land near 2**254 (e.g. arg_assets=2.15e76). The Forge PoC
# hardcodes those as uint256 constants; its own `assets * totalSupply` then
# overflows -> setUp reverts -> harness_error -> a REAL bug is demoted to
# informational. After a SAT we re-solve the SAME composed harness script with
# progressively tighter caps (tight->loose); the first SAT wins, giving the
# smallest groundable witness. If every rung is UNSAT the bug genuinely needs
# large magnitude (overflow class) and the ORIGINAL full-range witness is kept.
# The Phase-1 verdict is never changed -- only the witness is optionally shrunk,
# and a shrunk witness still satisfies every original constraint.
WITNESS_MINIMIZE_BOUNDS = tuple(
    int(x) for x in os.environ.get(
        "GODEL_WITNESS_BOUNDS", "1000000,1000000000000,1000000000000000000"
    ).split(",") if x.strip().isdigit()
)
# A counterexample value strictly above this is "ungroundable" (products risk
# uint256 overflow in the PoC), so minimization is attempted. Values at or below
# it are already realistic and skip the extra (LLM-free) re-solves.
WITNESS_GROUNDABLE_MAX = int(os.environ.get("GODEL_WITNESS_GROUNDABLE_MAX", 10**18))

# Z3 TIMEOUT RESCUE (decidability). An unbounded nonlinear integer property —
# mul/div of two uint256 symbols, e.g. `shares = (assets*totalSupply)/totalAssets`
# — can exceed Z3_TIMEOUT_SECONDS with no verdict: Z3 cannot decide nonlinear
# integer arithmetic in general. Re-solving the SAME harness-composed script with
# every symbol capped to [0, B] (build_model(witness_bound=B)) makes the domain
# finite, so it terminates. This is what stopped the seeded MiniVault deposit
# re-confirm: the specifier's property timed out at 30s, CEGIS burned LLM repairs
# that ALSO timed out, and the run aborted as analysis_incomplete after ~6 min.
# Tight->loose; the first SAT wins. A bounded SAT is a valid witness (only
# `sym <= B` was ADDED to the same property). A bounded UNSAT is NOT a safety
# proof — the violation may need larger magnitude — so only SAT is ever accepted;
# UNSAT/error fall through to the normal repair path. Starts small so a common
# small-witness bug (deposit: assets=1, totalSupply=1, totalAssets=1000) resolves
# on the first rung. Deterministic: no LLM call.
WITNESS_TIMEOUT_BOUNDS = tuple(
    int(x) for x in os.environ.get(
        "GODEL_WITNESS_TIMEOUT_BOUNDS", "65536,1000000,1000000000,1000000000000"
    ).split(",") if x.strip().isdigit()
)

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


def rag_enabled() -> bool:
    """Whether RAG grounding (ollama embeddings + cross-encoder rerank) runs.
    The stack is a ~26s cold load that CPU-offloads on <12GB GPUs and is
    reloaded after ollama's ~4-min keep-alive eviction; it only enriches
    DISCOVERY with historical findings. Set GODEL_DISABLE_RAG=1 to skip it —
    the MCP server defaults it on, because a targeted re-confirm already
    supplies the finding, so retrieval adds cost without changing the verdict."""
    return os.environ.get("GODEL_DISABLE_RAG", "0") not in ("1", "true", "True")


def setup_logging(level: str = None):
    """Two-tier logging: WARNING+ on the console (clean CI terminal), EVERYTHING
    to OUTPUT_DIR/godel-run-full.log (the noise tier persisted to the DB)."""
    root = logging.getLogger()
    if root.handlers:
        return
    level = level or os.environ.get("GODEL_LOG_LEVEL", "INFO")
    lvl = getattr(logging, str(level).upper(), logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")
    root.setLevel(lvl)

    console = logging.StreamHandler()
    if os.environ.get("GODEL_CONSOLE_DEBUG"):
        console.setLevel(lvl)
    else:
        console.setLevel(max(lvl, logging.WARNING))
    console.setFormatter(fmt)
    root.addHandler(console)

    try:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        fileh = logging.FileHandler(OUTPUT_DIR / "godel-run-full.log",
                                    mode="a", encoding="utf-8")
        fileh.setLevel(lvl)
        fileh.setFormatter(fmt)
        root.addHandler(fileh)
    except OSError:
        pass
