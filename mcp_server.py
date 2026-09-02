#!/usr/bin/env python3
"""mcp_server.py — Gödel's MCP face.

Exposes the audit engine as an MCP tool so AI assistants (opencode, Claude
Desktop, Cursor) can run a formal-verification audit inside a conversation.

Run locally:          python mcp_server.py
Install dependency:   pip install fastmcp

Register in opencode.json (project or global):
  {
    "mcp": {
      "godel": {
        "type": "local",
        "command": ["python", "C:\\\\Users\\\\AbdulWasay\\\\Desktop\\\\Ai Prototype\\\\mcp_server.py"],
        "cwd": "C:\\\\Users\\\\AbdulWasay\\\\Desktop\\\\Ai Prototype",
        "enabled": true
      }
    }
  }
"""

import os
import sys

# Make the repo root importable regardless of the working directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# MCP = targeted re-confirm/audit, so skip the RAG stack by default. warmup_rag()
# otherwise spends ~26s cold-loading qwen3-embedding:8b (4.7GB -> 7.2GB, CPU-
# offloaded on <12GB GPUs) BEFORE any verification work; when the MCP client's
# request timeout is shorter, it kills the call mid-load and ollama keeps loading
# as an orphan (the "VRAM fills after I kill it" symptom). setdefault so an
# opencode `environment` override (GODEL_DISABLE_RAG=0) can turn RAG back on.
os.environ.setdefault("GODEL_DISABLE_RAG", "1")

from contextlib import contextmanager

from fastmcp import FastMCP
from domain.pipeline import run_pipeline_code

mcp = FastMCP("godel")


@contextmanager
def _stdout_to_stderr():
    """Redirect stdout to stderr while the pipeline runs — at BOTH levels.

    fd-level: catches subprocesses and anything holding the raw handle.
    Object-level: catches buffered print() output that would otherwise sit in
    sys.stdout's buffer and flush into the JSON-RPC channel after restore.
    """
    sys.stdout.flush()
    saved_fd = os.dup(1)
    saved_stdout = sys.stdout
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    try:
        yield
    finally:
        try:
            sys.stdout.flush()
        except Exception:
            pass
        sys.stdout = saved_stdout
        os.dup2(saved_fd, 1)
        os.close(saved_fd)


@mcp.tool()
def audit_contract(
    contract_code: str,
    readme: str = "",
    target: str = "",
    prior_findings: list | dict | str | None = None,
    instructions: str = "",
) -> list:
    """Run Gödel formal verification on a Solidity contract.

    The mode is chosen automatically from which optional arguments you pass:

    - FULL AUDIT (default): pass `contract_code` (and the `readme` spec). Gödel
      discovers bugs, proves them with Z3, confirms each with a Foundry PoC, and
      proposes a fix — across every function.
    - SCOPED AUDIT: also pass `target` = a function name (e.g. "deposit") to
      restrict discovery to just that function. Faster and cheaper.
    - RE-CONFIRM A KNOWN FINDING: pass `prior_findings` — the finding dict(s)
      from an earlier run or a CI `finding.json` (a list, a single dict, or a
      JSON string). Gödel SKIPS discovery and re-verifies exactly those findings
      through Z3 + Foundry. Use this when CI failed, timed out, or left a
      finding unconfirmed and you want to re-target it with the same hypothesis.
    - DIRECTED HYPOTHESIS: pass `instructions` (free text, e.g. "check that a
      small deposit can mint zero shares when the share price is high"),
      optionally with `target`. Gödel verifies YOUR hypothesis instead of
      re-guessing one.

    `readme` is the formal specification / reachability answer-key: it states the
    invariants to prove and which states are reachable, which is what suppresses
    false positives. Always pass it when you have it.

    `contract_code` may be a whole contract or a bare fragment; a fragment with
    no enclosing contract/library/interface is auto-wrapped so it compiles. A
    fragment that needs external imports or base contracts still requires the
    surrounding code.

    Returns a list of finding dicts (contract, function, severity, summary,
    counterexample, z3 proof, Foundry PoC, forge output, fix, qc_status, ...).
    """
    with _stdout_to_stderr():
        return run_pipeline_code(
            contract_code,
            readme,
            target=target,
            prior_findings=prior_findings,
            instructions=instructions,
        )


if __name__ == "__main__":
    # Explicit stdio transport; stdout is reserved for JSON-RPC frames.
    mcp.run(transport="stdio")
