import json
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


def run_discovery(args) -> int:
    """Phase C: LLM-proposed invariant discovery, machine-verified by Z3.
    Proven properties and broken invariants (with counterexamples) land in
    output/reports/; broken ones additionally emit finding JSON."""
    from domain.config import CONTRACTS_FOLDER, REPORTS_FOLDER, FINDINGS_FOLDER
    from domain.abstracter import abstract_contract
    from domain.discovery import discover_invariants, default_discovery_llm
    from datetime import datetime

    folder = args.contracts or CONTRACTS_FOLDER
    if not folder or not os.path.isdir(folder):
        print(f"Invalid contracts folder for --discover: {folder!r}")
        return 1

    sol_files = []
    for root, _, files in os.walk(folder):
        sol_files.extend(os.path.join(root, f) for f in sorted(files) if f.endswith(".sol"))
    if not sol_files:
        print(f"No .sol files found in {folder}")
        return 1

    llm = default_discovery_llm()
    totals = {"proven": 0, "broken": 0, "inconclusive": 0, "rejected": 0}
    for path in sol_files:
        stem = os.path.splitext(os.path.basename(path))[0]
        analysis = abstract_contract(path)
        if analysis is None:
            print(f"\n[{stem}] static analysis unavailable — skipped (non-fatal)")
            continue
        print(f"\n=== DISCOVERY: {stem} (proposing -> proving) ===")
        result = discover_invariants(analysis, llm)
        for k in totals:
            totals[k] += len(result[k])

        for p in result["proven"]:
            print(f"   PROVEN       {p['invariant']}   [{p['verdict']}]")
        for b in result["broken"]:
            print(f"   BROKEN       {b['invariant']}   violated by {b['violated_by']}")
            for c in b.get("counterexamples", []):
                vals = ", ".join(f"{k}={v}" for k, v in sorted(c["assignments"].items()))
                print(f"                    cex in {c['function']}: {vals}")
        for i in result["inconclusive"]:
            print(f"   INCONCLUSIVE {i['invariant']}   [{i['verdict']}]")
        for rj in result["rejected"]:
            print(f"   rejected     {rj['invariant'][:60]} ({rj['reason'][:50]})")

        out_json = {
            "contract": result["contract"],
            "generated": datetime.now().isoformat(timespec="seconds"),
            **result,
        }
        with open(REPORTS_FOLDER / f"{stem}_discovery.json", "w", encoding="utf-8") as fh:
            json.dump(out_json, fh, indent=2)

        # Broken invariants become finding-shaped artifacts (gatekeeper/PoC
        # integration point for the graph pipeline).
        for idx, b in enumerate(result["broken"], 1):
            finding = {
                "contract": result["contract"],
                "function": (b["violated_by"] or ["contract-level"])[0],
                "severity": "high",
                "title": f"Invariant broken: {b['invariant']}",
                "summary": f"Discovered invariant '{b['invariant']}' is violated.",
                "root_cause": b["invariant"],
                "invariant": b["invariant"],
                "counterexamples": b.get("counterexamples", []),
                "metadata": {"timestamp": datetime.now().isoformat(timespec="seconds"),
                             "status": "broken_invariant", "source": "discovery"},
            }
            with open(FINDINGS_FOLDER / f"{stem}_invfinding_{idx}.json", "w",
                      encoding="utf-8") as fh:
                json.dump(finding, fh, indent=2)

    print(f"\n=== DISCOVERY SUMMARY: {totals['proven']} proven | "
          f"{totals['broken']} broken | {totals['inconclusive']} inconclusive | "
          f"{totals['rejected']} rejected ===")
    return 0


def run_wrap_probe(args) -> int:
    """Opt-in BitVec-256 wraparound triage over a contracts folder.
    Deterministic, LLM-free. Conservative: guards are NOT assumed."""
    from domain.config import CONTRACTS_FOLDER
    from domain.abstracter import abstract_contract
    from domain.wrap_probe import probe_contract

    folder = args.contracts or CONTRACTS_FOLDER
    if not folder or not os.path.isdir(folder):
        print(f"Invalid contracts folder for --wrap-probe: {folder!r}")
        return 1

    sol_files = []
    for root, _, files in os.walk(folder):
        sol_files.extend(os.path.join(root, f) for f in sorted(files) if f.endswith(".sol"))
    if not sol_files:
        print(f"No .sol files found in {folder}")
        return 1

    total_wrappable = 0
    for path in sol_files:
        analysis = abstract_contract(path)
        name = os.path.basename(path)
        if analysis is None:
            print(f"\n[{name}] static analysis unavailable — skipped (non-fatal)")
            continue
        rows = probe_contract(analysis)
        wrappable = [r for r in rows if r["wrap_reachable"]]
        total_wrappable += len(wrappable)
        print(f"\n[{name}] contract={analysis['contract']}  "
              f"arithmetic-writes={len(rows)}  WRAPPABLE={len(wrappable)}")
        for r in rows:
            mark = "WRAPPABLE " if r["wrap_reachable"] else "bounded/ok"
            print(f"   [{mark:>10}] {r['function']}: {r['write']}")

    print(f"\n=== WRAP PROBE RESULT: {total_wrappable} storage write(s) can "
          "wrap in a single call (guards NOT assumed — triage list) ===")
    return 0


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
    any_skipped = False
    verdicts = []
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
            # Contract simply has none of the referenced symbols (e.g. scanning
            # a mixed folder) — skip gracefully instead of killing the sweep.
            print(f"\n[{name}] invariant references none of its symbols — skipped ({e})")
            any_skipped = True
            continue
        verdicts.append(report["verdict"])
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
            elif r["status"] == "vacuously_preserved":
                print(f"   VACUOUSLY PRESERVED in {r['function']} "
                      f"(Inv(pre) unreachable — NOT a real proof)")
            elif r["status"] == "preserved_readonly":
                print(f"   trivially preserved in {r['function']} (read-only w.r.t. invariant)")
            elif r["status"] in ("error", "inconclusive"):
                any_error = True
                print(f"   {r['status'].upper()}: {r['function']}")

    if any_break:
        result_line = "BROKEN — see violating functions above"
    elif verdicts and all(v.startswith("INVARIANT PRESERVED") for v in verdicts):
        result_line = "HELD"
        if not all(v == "INVARIANT PRESERVED (exact)" for v in verdicts):
            result_line += " (under over-approximation)"
    else:
        # Inconclusive / possibly-violated / all-skipped: never print HELD.
        result_line = ("INCONCLUSIVE or PARTIAL — review POSSIBLY VIOLATED functions above;"
                       + (" some contracts skipped" if any_skipped else ""))
    print("\n=== INVARIANT MODE RESULT:", result_line, "===")
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
    parser.add_argument("--discover", action="store_true",
                        help="LLM-proposed invariant discovery: proposals are machine-proven/refuted by Z3 across all functions (one fast LLM call per contract)")
    parser.add_argument("--wrap-probe", action="store_true",
                        help="BitVec-256 wraparound triage: flag storage arithmetic that can overflow/underflow "
                             "in a single call (deterministic, conservative — guards not assumed)")
    args = parser.parse_args()

    if args.doctor:
        return run_doctor()

    if args.wrap_probe:
        return run_wrap_probe(args)

    if args.discover:
        return run_discovery(args)

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
