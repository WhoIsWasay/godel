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

from fastmcp import FastMCP
from domain.pipeline import run_pipeline_code

mcp = FastMCP("godel")


@mcp.tool()
def audit_contract(contract_code: str, readme: str = "") -> list:
    """Run Gödel formal verification on a Solidity contract.

    Returns a list of finding dicts (contract, function, severity, summary,
    counterexample, z3 proof, Foundry PoC, forge output, fix, qc_status, ...).
    """
    return run_pipeline_code(contract_code, readme)


if __name__ == "__main__":
    mcp.run()
