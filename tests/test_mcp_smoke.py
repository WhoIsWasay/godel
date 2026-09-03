"""Zero-credit MCP smoke test — proves mcp_server.py is plug-n-play.

Speaks the real JSON-RPC stdio handshake (initialize → tools/list) and
asserts audit_contract is advertised with the right schema. It NEVER calls
the tool, so no LLM credits are spent.

Run directly:  python tests/test_mcp_smoke.py
Or via pytest: pytest tests/test_mcp_smoke.py
"""

import json
import subprocess
import sys
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SERVER = [sys.executable, str(REPO_ROOT / "mcp_server.py")]


def _smoke():
    proc = subprocess.Popen(
        SERVER,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(REPO_ROOT),
        text=True,
        bufsize=1,
    )

    def drain():
        for _ in proc.stderr:
            pass

    threading.Thread(target=drain, daemon=True).start()

    def send(obj):
        proc.stdin.write(json.dumps(obj) + "\n")
        proc.stdin.flush()

    def recv(timeout=120):
        ready = [None]

        def reader():
            ready[0] = proc.stdout.readline()

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        t.join(timeout)
        if not ready[0]:
            raise TimeoutError("no response from MCP server")
        return ready[0]

    try:
        send({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "smoke-test", "version": "0.0"},
            },
        })
        resp = json.loads(recv())
        assert resp.get("id") == 1 and "result" in resp, f"bad initialize response: {resp}"
        assert resp["result"]["serverInfo"]["name"] == "godel"

        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        resp = json.loads(recv())
        tools = {t["name"]: t for t in resp["result"]["tools"]}
        assert "audit_contract" in tools, f"audit_contract missing, got: {sorted(tools)}"

        props = tools["audit_contract"]["inputSchema"]["properties"]
        assert "contract_code" in props and "readme" in props, sorted(props)
        # The injected FastMCP Context is server-side only; it must never leak
        # into the advertised input schema (regression guard for the async
        # keep-alive rewrite).
        assert "ctx" not in props, sorted(props)
        return tools
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_mcp_handshake():
    _smoke()


if __name__ == "__main__":
    tools = _smoke()
    print("MCP SMOKE TEST PASSED — tools:", sorted(tools), "(0 credits spent)")
