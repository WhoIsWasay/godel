import os
import sys
import shutil
import socket
import argparse

sys.stdout.reconfigure(encoding='utf-8')


def _version_of(binary: str, args: list) -> str:
    import subprocess
    try:
        r = subprocess.run([binary] + args, capture_output=True, text=True,
                           timeout=15, encoding="utf-8", errors="replace")
        first = (r.stdout or r.stderr or "").strip().splitlines()
        return first[0] if first else "ok"
    except FileNotFoundError:
        return None
    except Exception as e:
        return f"error: {e}"


def run_doctor() -> int:
    """Preflight readiness check for every external dependency of the engine.
    Exit code 1 only if a CRITICAL tool is missing."""
    return _doctor_impl()


def _doctor_impl() -> int:
    from dotenv import load_dotenv
    from domain.config import PROJECT_ROOT, FORGE_BIN, SOLC_BIN
    import importlib.util
    import httpx

    load_dotenv(PROJECT_ROOT / ".env")

    rows = []  # (criticality, name, status)
    def add(critical: bool, name: str, ok: bool, detail: str):
        rows.append((critical, name, "OK" if ok else "MISSING/FAIL", detail))

    # Foundry / solc / z3 / slither
    forge_ver = _version_of(FORGE_BIN, ["--version"])
    add(True, f"forge ({FORGE_BIN})", forge_ver is not None and not forge_ver.startswith("error"), forge_ver or "not found")
    solc_ver = _version_of(SOLC_BIN, ["--version"])
    add(True, f"solc ({SOLC_BIN})", solc_ver is not None and not solc_ver.startswith("error"), solc_ver or "not found")
    try:
        import z3
        add(True, "z3-solver", True, z3.get_version_string())
    except Exception as e:
        add(True, "z3-solver", False, str(e))
    slither_ok = importlib.util.find_spec("slither") is not None
    add(False, "slither", slither_ok, "installed" if slither_ok else "pip install slither-analyzer")

    # LLM key
    key = os.environ.get("DEEPSEEK_API_KEY", "")
    add(False, "DEEPSEEK_API_KEY", bool(key.strip()), "set" if key.strip() else ".env not configured?")

    # RAG stack (optional at audit time)
    ollama_url = os.environ.get("OLLAMA_URL", "http://localhost:11434")
    try:
        r = httpx.get(ollama_url + "/api/version", timeout=2)
        add(False, "ollama", r.status_code == 200, ollama_url)
    except Exception as e:
        add(False, "ollama", False, f"{ollama_url} unreachable ({type(e).__name__})")
    pg_host = os.environ.get("PGHOST", "localhost")
    pg_port = int(os.environ.get("PGPORT", "5433"))
    try:
        with socket.create_connection((pg_host, pg_port), timeout=2):
            add(False, "postgres (paradedb)", True, f"{pg_host}:{pg_port}")
    except Exception:
        add(False, "postgres (paradedb)", False, f"{pg_host}:{pg_port} unreachable — RAG disabled")

    width = max(len(r[1]) for r in rows)
    print("\n=== GÖDEL DOCTOR ===")
    for critical, name, status, detail in rows:
        mark = "*" if critical else " "
        color = "" if status == "OK" else ("  <-- REQUIRED" if critical else "")
        print(f" {mark} {name:<{width}}  [{status}]{color}")
        if detail:
            print(f"      {detail}")
    crit_fail = any(c and s != "OK" for c, _, s, _ in rows)
    print("=== RESULT:", "NOT READY — fix required items (*) ===" if crit_fail else "READY ===")
    return 1 if crit_fail else 0


def run_invariant_mode(args) -> int:
    """Deterministic invariant-preservation checking over a contracts folder.
    No LLM calls: static analysis + Z3 only."""
    from domain.config import CONTRACTS_FOLDER
    from domain.abstracter import abstract_contract
    from domain.invariants import check_invariant_preservation, InvariantSyntaxError

    folder = args.contracts or CONTRACTS_FOLDER
    if not folder or not os.path.isdir(folder):
        print(f"Invalid contracts folder for --invariant mode: {folder!r}")
        return 1

    sol_files = []
    for root, _, files in os.walk(folder):
        sol_files.extend(os.path.join(root, f) for f in sorted(files) if f.endswith(".sol"))
    if not sol_files:
        print(f"No .sol files found in {folder}")
        return 1

    any_break, any_error = False, False
    for path in sol_files:
        analysis = abstract_contract(path)
        name = os.path.basename(path)
        if analysis is None:
            print(f"\n[{name}] static analysis unavailable — skipped (non-fatal)")
            any_error = True
            continue
        try:
            report = check_invariant_preservation(analysis, args.invariant)
        except InvariantSyntaxError as e:
            print(f"\n[{name}] invariant rejected: {e}")
            return 1
        print(f"\n[{name}] contract={report['contract']}  verdict={report['verdict']}")
        if report["violated_by"]:
            any_break = True
            for r in report["details"]:
                if r["status"] == "violated":
                    cex = (r.get("counterexample") or {}).get("assignments") or {}
                    vals = ", ".join(f"{k}={v}" for k, v in sorted(cex.items()))
                    print(f"   VIOLATED by {r['function']}"
                          + (f"  counterexample: {vals}" if vals else ""))
        for r in report["details"]:
            if r["status"] == "possibly_violated":
                print(f"   POSSIBLY VIOLATED in {r['function']} "
                      f"[over-approximated model — manual review]")
            elif r["status"] == "not_modeled":
                print(f"   NOT MODELED: {r['function']} (writes referenced state "
                      f"the encoder cannot represent)")
            elif r["status"] == "preserved":
                print(f"   preserved in {r['function']}  [{r.get('quality')}]")
            elif r["status"] == "preserved_readonly":
                print(f"   trivially preserved in {r['function']} (read-only w.r.t. invariant)")
            elif r["status"] in ("error", "inconclusive"):
                any_error = True
                print(f"   {r['status'].upper()}: {r['function']}")

    print("\n=== INVARIANT MODE RESULT:",
          "BROKEN — see violating functions above ===" if any_break else "HELD ===")
    return 1 if any_break else 0


def main():
    parser = argparse.ArgumentParser(description="Gödel multi-agent Solidity audit pipeline")
    parser.add_argument("--contracts", default=None, help="Path to the folder of .sol files to audit")
    parser.add_argument("--dry-run", action="store_true", help="Validate plumbing without calling LLMs")
    parser.add_argument("--timeout", type=float, default=None, help="Per-function timeout in seconds")
    parser.add_argument("--doctor", action="store_true", help="Preflight check of external tools (forge/solc/z3/slither/RAG)")
    parser.add_argument("--invariant", default=None, metavar="EXPR",
                        help="Contract-wide invariant mode: check preservation of EXPR across all public "
                             "functions (deterministic, no LLM). Post-state keys use '@new', e.g. "
                             "\"total@new == bal[S]@new\"")
    args = parser.parse_args()

    if args.doctor:
        return run_doctor()

    if args.invariant:
        return run_invariant_mode(args)

    # Set env vars BEFORE importing the pipeline so domain.config picks them up.
    if args.dry_run:
        os.environ["GODEL_DRY_RUN"] = "1"
    if args.timeout is not None:
        os.environ["GODEL_PER_FUNCTION_TIMEOUT"] = str(args.timeout)

    from domain.config import CONTRACTS_FOLDER
    from domain.pipeline import run_pipeline

    folder = args.contracts or CONTRACTS_FOLDER
    results = run_pipeline(folder)

    print(f"\n=== SUMMARY: {len(results)} verified finding(s) ===")
    for r in results:
        print(f"  [{r.get('severity', 'unknown').upper()}] {r.get('contract')}::{r.get('function')} ({r.get('qc_status', 'unknown')})")

    return results


if __name__ == "__main__":
    main()
