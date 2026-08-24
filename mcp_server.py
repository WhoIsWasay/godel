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
def audit_contract(contract_code: str, readme: str = "") -> list:
    """Run Gödel formal verification on a Solidity contract.

    Returns a list of finding dicts (contract, function, severity, summary,
    counterexample, z3 proof, Foundry PoC, forge output, fix, qc_status, ...).
    """
    with _stdout_to_stderr():
        return run_pipeline_code(contract_code, readme)


if __name__ == "__main__":
    # Explicit stdio transport; stdout is reserved for JSON-RPC frames.
    mcp.run(transport="stdio")
