#!/usr/bin/env python3
"""ci_summary.py — emits a GitHub job-summary markdown table of verified findings.

Zero LLM calls: reads output/submissions/**/finding.json and prints markdown.
CI wires it as:  python ci_summary.py >> "$GITHUB_STEP_SUMMARY"
Falls back to a "no findings" line so the summary is always meaningful.
"""

import json
import sys
from pathlib import Path

from domain import config

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
CONFIRMED = {"confirmed", "broken_invariant"}


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    submissions = Path(sys.argv[1]) if len(sys.argv) > 1 else config.SUBMISSIONS_FOLDER
    rows = []
    for jf in sorted(submissions.rglob("finding.json")):
        try:
            f = json.loads(jf.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        rows.append(f)

    print("## Gödel Audit — Verified Findings")
    print()
    if not rows:
        print("✅ **0 verified findings** — no exploit was mathematically proven this run.")
        return

    rows.sort(key=lambda f: (SEV_ORDER.get((f.get("severity") or "").lower(), 9),
                             f.get("contract", ""), f.get("function", "")))
    high = sum(1 for f in rows if (f.get("severity") or "").lower() in ("critical", "high"))
    confirmed = sum(1 for f in rows if (f.get("qc_status") or "").lower() in CONFIRMED)
    print(f"**{len(rows)} verified finding(s)** — {high} critical/high · "
          f"{confirmed} reproduced on-chain via Foundry PoC")
    print()
    print("| Sev | Contract | Function | Verdict | Title |")
    print("|-----|----------|----------|---------|-------|")
    for f in rows:
        sev = (f.get("severity") or "?").upper()
        qc = f.get("qc_status") or "?"
        verdict = "✅ reproduced on-chain" if qc in CONFIRMED else qc
        title = (f.get("title") or "Finding").splitlines()[0][:100]
        print(f"| {sev} | `{f.get('contract', '?')}` | `{f.get('function', '?')}` "
              f"| {verdict} | {title} |")
    print()
    print("Full details, Z3 counterexamples, PoC tests and fixes: download the "
          "**godel-findings** artifact (`output/rendered/<Contract>/index.html`).")


if __name__ == "__main__":
    main()
