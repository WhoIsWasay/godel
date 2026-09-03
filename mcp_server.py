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
import time

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

import anyio
from fastmcp import Context, FastMCP

from domain import config

# Import the pipeline at MODULE TOP (main thread), NOT lazily inside the tool's
# worker thread. domain.pipeline transitively imports numpy (whose C-extension
# loader deadlocks on Windows when first imported from a non-main thread while
# the asyncio event loop is running — it hung the worker for 90s+ and the tool
# never returned). Loading it here, once, on the main thread during startup
# avoids that entirely; the ~4s cost is paid before the initialize handshake
# and every later import is a cached no-op.
from domain.pipeline import run_pipeline_code

mcp = FastMCP("godel")


class _StderrSink:
    """File-like that forwards writes to stderr, leaving fd 1 (the JSON-RPC
    channel) pristine. `__getattr__` delegates anything else (fileno, buffer,
    writable, …) to sys.stderr so a stray caller that reaches for a raw handle
    still lands on stderr instead of fd 1."""

    def write(self, s):
        try:
            sys.stderr.write(s)
            sys.stderr.flush()
        except Exception:
            pass
        return len(s)

    def flush(self):
        try:
            sys.stderr.flush()
        except Exception:
            pass

    def isatty(self):
        return False

    def __getattr__(self, name):
        return getattr(sys.stderr, name)


@contextmanager
def _stdout_to_stderr():
    """Route the pipeline's stdout to stderr for one tool call — OBJECT-LEVEL.

    The previous version also did fd-level `os.dup2(2, 1)`, which retargeted
    fd 1 to stderr for the whole call. But the MCP stdio transport captured
    `sys.stdout.buffer` (fd 1) at server startup, so EVERY JSON-RPC frame
    written during the run — the tool result AND any progress/keep-alive
    notifications — went to stderr and never reached the client. The client saw
    a silent channel and idle-timed-out the call ("MCP tool timed out").

    Rebinding `sys.stdout` alone keeps fd 1 pristine so those frames still reach
    the client, while every `print()` in the pipeline goes to stderr. This is
    safe because all subprocesses in the hot path (forge, z3, solc) are spawned
    with capture_output=True, so none inherits fd 1.
    """
    saved = sys.stdout
    sys.stdout = _StderrSink()
    try:
        yield
    finally:
        try:
            sys.stderr.flush()
        except Exception:
            pass
        sys.stdout = saved


async def _run_with_heartbeat(run_blocking, emit, interval):
    """Run the blocking callable `run_blocking` in a worker thread while calling
    `await emit(n)` every `interval` seconds until it finishes.

    Returns run_blocking()'s result and re-raises its exception. `emit` errors
    are swallowed (a keep-alive must never fail the audit). `interval <= 0`
    disables heartbeats and simply awaits the worker (guarding against a
    busy-spin). The worker thread is not cancellable, so a client disconnect
    still lets the pipeline finish in the background — unchanged from before.
    """
    if not interval or interval <= 0:
        return await anyio.to_thread.run_sync(run_blocking)

    box: dict = {}
    done = anyio.Event()

    async def _worker():
        try:
            box["result"] = await anyio.to_thread.run_sync(run_blocking)
        except Exception as exc:  # re-raised to the caller after the loop ends
            box["error"] = exc
        finally:
            done.set()

    n = 0
    async with anyio.create_task_group() as tg:
        tg.start_soon(_worker)
        while not done.is_set():
            with anyio.move_on_after(interval):
                await done.wait()
            if done.is_set():
                break
            n += 1
            try:
                await emit(n)
            except Exception:
                pass

    if "error" in box:
        raise box["error"]
    return box.get("result")


def _mode_label(target: str, prior_findings, instructions: str) -> str:
    """Human-readable mode for the keep-alive message (mirrors the dispatcher)."""
    if prior_findings:
        return "re-confirm"
    if instructions:
        return "directed hypothesis"
    if target:
        return f"scoped audit ({target})"
    return "full audit"


def _make_emitter(ctx: Context, mode: str):
    """Build the per-call keep-alive emitter.

    report_progress only reaches clients that sent a progressToken; ctx.info
    (an MCP logging notification) reaches ALL clients by default. Emitting both
    guarantees the channel shows activity regardless of client capability, which
    is what stops an idle-timeout during the multi-minute Z3 + Foundry run.
    """
    started = time.monotonic()

    async def emit(n: int) -> None:
        elapsed = time.monotonic() - started
        msg = f"Gödel {mode}: {elapsed:.0f}s elapsed, still verifying (heartbeat {n})"
        try:
            await ctx.report_progress(n, None, msg)
        except Exception:
            pass
        try:
            await ctx.info(msg)
        except Exception:
            pass

    return emit


@mcp.tool()
async def audit_contract(
    ctx: Context,
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

    This is a long-running call (Z3 + Foundry + LLM). It emits MCP progress /
    logging notifications while it works, so keep the connection open rather
    than treating a period without a final result as a timeout.

    Returns a list of finding dicts (contract, function, severity, summary,
    counterexample, z3 proof, Foundry PoC, forge output, fix, qc_status, ...).
    """
    mode = _mode_label(target, prior_findings, instructions)

    def _blocking():
        with _stdout_to_stderr():
            return run_pipeline_code(
                contract_code,
                readme,
                target=target,
                prior_findings=prior_findings,
                instructions=instructions,
            )

    return await _run_with_heartbeat(
        _blocking, _make_emitter(ctx, mode), config.MCP_HEARTBEAT_SECONDS
    )


if __name__ == "__main__":
    # Explicit stdio transport; stdout is reserved for JSON-RPC frames.
    mcp.run(transport="stdio")
