"""Regression corpus runner: walks TestsDone/ (and optionally other folders),
runs the deterministic engine stack over every .sol file (static analysis ->
harness generation -> invariant smoke), and asserts graceful behavior.

This is the LLM-free regression net: it cannot prove bug-detection (that needs
live audits) but catches parser/encoder/verdict regressions instantly.

Run:  python -X utf8 testOfCode/run_corpus.py [folder]
Exit code 0 = corpus healthy.
"""
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from domain.abstracter import abstract_contract            # noqa: E402
from domain.semantics import generate_harness              # noqa: E402
from domain.invariants import check_invariant_preservation # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Default corpus: the private TestsDone/ benchmark folder when present
# (local machine), otherwise the committed fixtures (CI / fresh clones).
_private = os.path.join(ROOT, "TestsDone")
FOLDER = sys.argv[1] if len(sys.argv) > 1 else (
    _private if os.path.isdir(_private) else os.path.join(ROOT, "testOfCode", "fixtures"))

files = []
for root, _, names in os.walk(FOLDER):
    for n in sorted(names):
        if n.endswith(".sol"):
            files.append(os.path.join(root, n))

if not files:
    print(f"No .sol files found under {FOLDER} — nothing to smoke "
          "(fixtures/corpus are intentionally not committed). Exiting clean.")
    sys.exit(0)

print(f"=== CORPUS RUNNER: {len(files)} file(s) under {os.path.relpath(FOLDER, ROOT)} ===\n")
ok = analyzed = harness_ok = inv_ran = 0
crashed = []

for path in files:
    rel = os.path.relpath(path, ROOT)
    ok += 1
    try:
        analysis = abstract_contract(path)
        if analysis is None:
            print(f"  [{rel}] static-analysis unavailable (pragma/deps) — skipped gracefully")
            continue
        analyzed += 1
        fns = list(analysis.get("functions", {}).keys())
        harnesses = [generate_harness(analysis, fn) for fn in fns]
        n_ok = sum(1 for h in harnesses if h)
        harness_ok += n_ok
        print(f"  [{rel}] contract={analysis['contract']} functions={len(fns)} "
              f"harnesses={n_ok} detectors={len(analysis.get('detectors', []))}")

        # invariant smoke on first storage scalar (or fallback constant-zero)
        storage = analysis.get("storage_layout", [])
        if storage:
            base = storage[0]["name"]
            inv = f"{base}@new >= 0"
            rep = check_invariant_preservation(analysis, inv)
            inv_ran += 1
            assert rep["verdict"], "empty verdict"
            print(f"      invariant smoke '{inv}' -> {rep['verdict']}")
    except Exception as e:
        crashed.append((rel, f"{type(e).__name__}: {e}"))
        traceback.print_exc()

print(f"\n=== SUMMARY: {ok} files | {analyzed} analyzed | {harness_ok} harnesses | "
      f"{inv_ran} invariant smokes | {len(crashed)} CRASHES ===")

if crashed:
    print("\nCRASHES (engine must never crash on input):")
    for rel, err in crashed:
        print(f"  {rel}: {err}")
sys.exit(1 if crashed else 0)
