#!/usr/bin/env python3
"""render.py — turns per-finding finding.json files into GitHub-flavored markdown
and standalone HTML reports for the Gödel audit results site.

Consumes:  <submissions>/<contract>/<function>/finding.json   (one per finding)
Produces:  <out>/<contract>/README.md  +  <out>/<contract>/index.html

Severity badges, collapsed PoC, and counterexample tables are generated so the
CI/CD render layer (and the "Claude UI") have a single, clean artifact source.
"""

import argparse
import html
import json
from pathlib import Path

from domain.schema import normalize_counterexample

SEVERITY_HTML_COLORS = {
    "critical": "#b60205",
    "high": "#d73a49",
    "medium": "#dbab09",
    "low": "#0e8a16",
    "info": "#3178c6",
}

SEVERITY_SHIELDS = {
    "critical": "red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
    "info": "lightgrey",
}


def _sev(severity):
    return (severity or "unknown").lower()


def badge_md(severity):
    s = _sev(severity)
    color = SEVERITY_SHIELDS.get(s, "lightgrey")
    return f"![{s}](https://img.shields.io/badge/severity-{s}-{color})"


def badge_html(severity):
    s = _sev(severity)
    color = SEVERITY_HTML_COLORS.get(s, "#6a737d")
    return (f'<span class="badge" style="background:{color};color:#fff;'
            f'padding:2px 10px;border-radius:12px;font-weight:600;">{s.upper()}</span>')


def counterexample_table_md(cex):
    cex = normalize_counterexample(cex)
    if not cex:
        return "_No counterexample values captured._"
    lines = ["| Variable | Value |", "|---|---|"]
    for k, v in cex.items():
        lines.append(f"| `{k}` | `{v}` |")
    return "\n".join(lines)


def counterexample_table_html(cex):
    cex = normalize_counterexample(cex)
    if not cex:
        return "<p><em>No counterexample values captured.</em></p>"
    rows = "".join(
        f"<tr><td><code>{html.escape(str(k))}</code></td>"
        f"<td><code>{html.escape(str(v))}</code></td></tr>"
        for k, v in cex.items()
    )
    return (f"<table><thead><tr><th>Variable</th><th>Value</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>")


def _block_md(title, content):
    content = content or "_none_"
    return f"<details>\n<summary>{title}</summary>\n\n```solidity\n{content}\n```\n\n</details>"


def _block_html(title, content):
    content = content or "_none_"
    return (f"<details><summary>{title}</summary>"
            f"<pre><code>{html.escape(str(content))}</code></pre></details>")


def finding_to_md(f):
    parts = [
        f"## {badge_md(f.get('severity'))} `{f.get('function', 'unknown')}`",
        f"**{f.get('title', 'Finding')}**",
        "",
        f"- **Summary:** {f.get('summary', '')}",
        f"- **Root cause:** `{f.get('root_cause', '')}`",
        f"- **Invariant:** `{f.get('invariant', '')}`",
        f"- **QC status:** `{f.get('qc_status', 'unknown')}`",
        "",
        "### Counterexample",
        counterexample_table_md(f.get("counterexample")),
        "",
        "### Proof of Concept (PoC)",
        _block_md("PoC test (Foundry)", f.get("poc_test_code")),
        "",
        "### Proof of Exploitability (Z3)",
        _block_md("Z3 proof", f.get("z3_proof_code")),
        "",
        "### Vulnerable code slice",
        _block_md("Isolated code", f.get("isolated_code")),
        "",
        "### Recommended fix",
        _block_md("Fix", f.get("fix_code")),
        "",
        "### Forge output",
        _block_md("Forge output", f.get("forge_output")),
    ]
    return "\n".join(parts)


def finding_to_html(f):
    return f"""
<article class="finding">
  <h3>{badge_html(f.get('severity'))} <code>{html.escape(str(f.get('function', 'unknown')))}</code></h3>
  <p class="title">{html.escape(str(f.get('title', 'Finding')))}</p>
  <p><strong>Summary:</strong> {html.escape(str(f.get('summary', '')))}</p>
  <p><strong>Root cause:</strong> <code>{html.escape(str(f.get('root_cause', '')))}</code></p>
  <p><strong>Invariant:</strong> <code>{html.escape(str(f.get('invariant', '')))}</code></p>
  <p><strong>QC status:</strong> <code>{html.escape(str(f.get('qc_status', 'unknown')))}</code></p>
  <h4>Counterexample</h4>
  {counterexample_table_html(f.get('counterexample'))}
  <h4>Proof of Concept (PoC)</h4>
  {_block_html('PoC test (Foundry)', f.get('poc_test_code'))}
  <h4>Proof of Exploitability (Z3)</h4>
  {_block_html('Z3 proof', f.get('z3_proof_code'))}
  <h4>Vulnerable code slice</h4>
  {_block_html('Isolated code', f.get('isolated_code'))}
  <h4>Recommended fix</h4>
  {_block_html('Fix', f.get('fix_code'))}
  <h4>Forge output</h4>
  {_block_html('Forge output', f.get('forge_output'))}
</article>
"""


def collect_findings(submissions_dir):
    """Walk <submissions>/<contract>/<function>/finding.json -> {contract: [findings]}."""
    root = Path(submissions_dir)
    grouped = {}
    for jf in sorted(root.rglob("finding.json")):
        try:
            finding = json.loads(jf.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        contract = finding.get("contract") or jf.parent.parent.name
        grouped.setdefault(contract, []).append(finding)
    return grouped


def severity_sort_key(f):
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(_sev(f.get("severity")), 9)


def render_contract_md(contract, findings):
    findings = sorted(findings, key=severity_sort_key)
    total = len(findings)
    high = sum(1 for f in findings if _sev(f.get("severity")) in ("critical", "high"))
    header = [
        f"# {contract} — Gödel Audit",
        "",
        f"**Findings:** {total} | **Critical/High:** {high}",
        "",
    ]
    body = [finding_to_md(f) for f in findings]
    return "\n\n".join(header + body)


def render_contract_html(contract, findings):
    findings = sorted(findings, key=severity_sort_key)
    cards = "\n".join(finding_to_html(f) for f in findings)
    total = len(findings)
    high = sum(1 for f in findings if _sev(f.get("severity")) in ("critical", "high"))
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(contract)} — Gödel Audit</title>
<style>
body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0d1117; color:#c9d1d9; margin:0; padding:2rem; }}
h1 {{ color:#fff; }}
.badge {{ display:inline-block; }}
code {{ background:#161b22; padding:2px 6px; border-radius:4px; }}
.finding {{ border:1px solid #30363d; border-radius:8px; padding:1.25rem; margin:1rem 0; background:#161b22; }}
.finding h3 {{ margin-top:0; color:#fff; }}
table {{ border-collapse:collapse; margin:0.5rem 0 1rem; }}
th, td {{ border:1px solid #30363d; padding:6px 12px; text-align:left; }}
details {{ margin:0.5rem 0; }}
summary {{ cursor:pointer; font-weight:600; color:#58a6ff; }}
pre {{ background:#0d1117; padding:0.75rem; border-radius:6px; overflow-x:auto; }}
pre code {{ background:transparent; padding:0; }}
</style>
</head>
<body>
<h1>{html.escape(contract)} — Gödel Audit</h1>
<p><strong>Findings:</strong> {total} &nbsp; <strong>Critical/High:</strong> {high}</p>
{cards}
</body>
</html>
"""


def render(submissions_dir, out_dir):
    grouped = collect_findings(submissions_dir)
    if not grouped:
        print(f"No finding.json files found under {submissions_dir}")
        return 0
    out = Path(out_dir)
    count = 0
    for contract, findings in grouped.items():
        cdir = out / contract
        cdir.mkdir(parents=True, exist_ok=True)
        (cdir / "README.md").write_text(render_contract_md(contract, findings), encoding="utf-8")
        (cdir / "index.html").write_text(render_contract_html(contract, findings), encoding="utf-8")
        count += 1
        print(f"Rendered {contract}: {len(findings)} finding(s) -> {cdir}")
    return count


def main():
    from domain import config  # anchor default paths

    parser = argparse.ArgumentParser(description="Render finding.json files to Markdown + HTML")
    parser.add_argument("--submissions", default=str(config.SUBMISSIONS_FOLDER),
                        help="Path to the submissions folder (default: config.SUBMISSIONS_FOLDER)")
    parser.add_argument("--out", default=str(config.OUTPUT_DIR / "rendered"),
                        help="Output directory (default: <output>/rendered)")
    args = parser.parse_args()

    n = render(args.submissions, args.out)
    print(f"\nRendered {n} contract(s) to {args.out}")


if __name__ == "__main__":
    main()
