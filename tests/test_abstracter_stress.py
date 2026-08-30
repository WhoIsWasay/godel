"""
Comprehensive dry-run stress test for Godel abstracter + state management.
Zero API calls. Run: python -m pytest tests/test_abstracter_stress.py -v
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from domain.abstracter import (
    render_cfg_slice,
    detect_compositional_candidates,
    render_compositional_context,
)
from domain.pipeline import (
    extract_functions_from_xml,
    scope_functions_to_primary_contract,
    is_read_only_function,
)


def _fn(vis="public", mods=None, params=None, rets=None, nodes=4, edges=4, loops=0,
        sw=None, sr=None, ext=None, hec=False, guards=None, assigns=None,
        fec=None, bcs=None, hb=False, ret=None, ic=None, brs=None, pay=False):
    return {
        "full_name": "", "visibility": vis, "modifiers": mods or [],
        "params": params or [], "returns_types": rets or [],
        "nodes": nodes, "edges": edges, "loops": loops,
        "state_writes": sw or [], "state_reads": sr or [],
        "external_calls": ext or [], "has_external_call": hec,
        "guards": guards or [], "assignments": assigns or [],
        "first_external_call_order": fec,
        "branch_conditions_src": bcs or [], "has_branch": hb,
        "returns_expr": ret, "internal_calls": ic or [],
        "branches": brs or [], "payable": pay,
    }


def _truster():
    return {
        "file": "/tmp/T.sol", "sha256": "abc", "solc_version": "0.8.19",
        "contract": "TrusterLenderPool",
        "functions": {
            "flashLoan(uint256,address,address,bytes)": _fn(
                vis="public", mods=["nonReentrant"], nodes=14, edges=18,
                sr=["allowance"], ext=["functionCall", "transferFrom"], hec=True,
                guards=["amount > 0"], fec=3, bcs=["amount > 0"], hb=True,
                brs=[{"kind": "require", "expr": "amount > 0"}]),
            "approve(address,uint256)": _fn(
                rets=["bool"], sw=["allowance"], ret="true"),
            "withdraw(uint256)": _fn(
                nodes=6, edges=7, sw=["balance"], sr=["balance", "owner"],
                ext=["transfer"], hec=True, guards=["msg.sender == owner"],
                fec=2, bcs=["msg.sender == owner"], hb=True,
                brs=[{"kind": "require", "expr": "msg.sender == owner"}]),
            "totalSupply()": _fn(
                nodes=2, edges=2, rets=["uint256"], sr=["totalSupply"], ret="totalSupply"),
            "transfer(address,uint256)": _fn(
                nodes=8, edges=10, rets=["bool"], sw=["balance"], sr=["balance"],
                guards=["to != address(0)"], hb=True, ret="true"),
        },
        "detectors": [
            {"impact": "High", "check": "arbitrary-send-erc20", "description": "transferFrom"},
            {"impact": "Medium", "check": "reentrancy", "description": "Reentrancy in flashLoan"},
        ],
        "storage_layout": [
            {"name": "allowance", "type": "mapping"},
            {"name": "balance", "type": "mapping"},
            {"name": "owner", "type": "address"},
        ],
    }


def _vault():
    return {
        "file": "/tmp/V.sol", "sha256": "def", "solc_version": "0.8.20",
        "contract": "Vault",
        "functions": {
            "batchProcess(address[],uint256[])": _fn(
                vis="external", mods=["onlyOwner"], nodes=20, edges=30, loops=1,
                sw=["balance", "processed"], sr=["balance", "owner", "cap"],
                ext=["transfer"], hec=True,
                guards=["recipients.length == amounts.length"], fec=4,
                bcs=["i < recipients.length"], hb=True,
                ic=["_validate", "_updateAccounting"],
                brs=[
                    {"kind": "require", "expr": "recipients.length == amounts.length"},
                    {"kind": "ifloop", "expr": "i < recipients.length"},
                ]),
            "deposit()": _fn(
                vis="external", nodes=5, edges=5,
                sw=["balance", "totalDeposits"], sr=["balance"],
                guards=["msg.value > 0"], bcs=["msg.value > 0"], hb=True,
                brs=[{"kind": "require", "expr": "msg.value > 0"}], pay=True),
            "_validate(uint256)": _fn(
                vis="internal", nodes=3, edges=3, sr=["cap"],
                guards=["amount <= cap"], hb=True, ret="true",
                brs=[{"kind": "require", "expr": "amount <= cap"}]),
            "_updateAccounting()": _fn(
                vis="internal", nodes=3, edges=3,
                sw=["lastUpdate"], sr=["lastUpdate"]),
        },
        "detectors": [],
        "storage_layout": [{"name": "balance", "type": "mapping"}],
    }


# === 1. CFG RENDERING ===
class TestCfg:
    def test_focus(self):
        b = render_cfg_slice(_truster(), "flashLoan")
        assert "<cfg_abstraction" in b and "flashLoan" in b and "allowance" in b

    def test_detectors(self):
        assert "arbitrary-send-erc20" in render_cfg_slice(_truster(), "flashLoan")

    def test_payable(self):
        assert 'payable="true"' in render_cfg_slice(_vault(), "deposit")

    def test_branches(self):
        assert "amount > 0" in render_cfg_slice(_truster(), "flashLoan")

    def test_loops(self):
        b = render_cfg_slice(_vault(), "batchProcess")
        assert 'loops="1"' in b and "ifloop" in b

    def test_callees(self):
        b = render_cfg_slice(_vault(), "batchProcess")
        assert "<callee_cfg" in b and "_validate" in b

    def test_unknown_empty(self):
        assert render_cfg_slice(_truster(), "nonexistent") == ""

    def test_none_empty(self):
        assert render_cfg_slice(None, "x") == ""

    def test_empty_fns(self):
        assert render_cfg_slice({"functions": {}}, "x") == ""

    def test_truncation(self):
        b = render_cfg_slice(_vault(), "batchProcess", max_chars=200)
        assert len(b) <= 200 and "[cfg_abstraction truncated]" in b

    def test_no_truncation(self):
        b = render_cfg_slice(_truster(), "flashLoan", max_chars=50000)
        assert "[cfg_abstraction truncated]" not in b

    def test_name_strip_params(self):
        b = render_cfg_slice(_truster(), "flashLoan(uint256,address,address,bytes)")
        assert "<cfg_abstraction" in b

    def test_reads_capped_14(self):
        a = _truster()
        a["functions"]["flashLoan(uint256,address,address,bytes)"]["state_reads"] = [f"v_{i}" for i in range(20)]
        b = render_cfg_slice(a, "flashLoan")
        line = [l for l in b.split("\n") if "<storage_reads>" in l][0]
        assert len(line.split(">")[1].split("<")[0].split(", ")) == 14


# === 2. COMPOSITIONAL DETECTION ===
class TestCompDetect:
    def test_approve_flashloan(self):
        cs = detect_compositional_candidates(_truster())
        p = [c for c in cs if {c["writer"], c["reader"]} == {"approve", "flashLoan"}]
        assert len(p) == 1 and p[0]["risk"] == "high" and "allowance" in p[0]["shared_state"]

    def test_transfer_withdraw(self):
        cs = detect_compositional_candidates(_truster())
        p = [c for c in cs if {c["writer"], c["reader"]} == {"transfer", "withdraw"}]
        assert len(p) == 1 and "balance" in p[0]["shared_state"]

    def test_risk_ordering(self):
        cs = detect_compositional_candidates(_truster())
        risks = [c["risk"] for c in cs]
        hi = [i for i, r in enumerate(risks) if r == "high"]
        lo = [i for i, r in enumerate(risks) if r == "low"]
        if hi and lo:
            assert hi[0] < lo[0]

    def test_limit_10(self):
        a = {"functions": {}}
        for i in range(30):
            a["functions"][f"w_{i}()"] = {"state_writes": ["v"], "state_reads": []}
            a["functions"][f"r_{i}()"] = {"state_writes": [], "state_reads": ["v"]}
        assert len(detect_compositional_candidates(a)) <= 10

    def test_none(self):
        assert detect_compositional_candidates(None) == []

    def test_empty(self):
        assert detect_compositional_candidates({"functions": {}}) == []

    def test_no_shared(self):
        a = {"functions": {"f()": {"state_writes": ["x"], "state_reads": []},
                           "g()": {"state_writes": ["y"], "state_reads": []}}}
        assert detect_compositional_candidates(a) == []

    def test_no_self(self):
        a = {"functions": {"f()": {"state_writes": ["x"], "state_reads": ["x"]}}}
        assert all(c["writer"] != c["reader"] for c in detect_compositional_candidates(a))

    def test_medium_admin(self):
        a = {"functions": {
            "setAdmin()": {"state_writes": ["admin"], "state_reads": [], "external_calls": []},
            "do()": {"state_writes": [], "state_reads": ["admin"], "external_calls": []}}}
        cs = detect_compositional_candidates(a)
        assert cs and cs[0]["risk"] == "medium"

    def test_low_generic(self):
        a = {"functions": {
            "setCfg()": {"state_writes": ["cfg"], "state_reads": [], "external_calls": []},
            "getCfg()": {"state_writes": [], "state_reads": ["cfg"], "external_calls": []}}}
        cs = detect_compositional_candidates(a)
        assert cs and cs[0]["risk"] == "low"

    def test_high_transfers(self):
        a = {"functions": {
            "setApproval()": {"state_writes": ["approval"], "state_reads": [], "external_calls": []},
            "drain()": {"state_writes": [], "state_reads": ["approval"], "external_calls": ["transferFrom"]}}}
        cs = detect_compositional_candidates(a)
        assert cs and cs[0]["risk"] == "high"


# === 3. COMPOSITIONAL CONTEXT ===
class TestCompCtx:
    def test_writer(self):
        ctx = render_compositional_context(_truster(), "approve")
        assert "<compositional_context>" in ctx and "allowance" in ctx

    def test_reader(self):
        ctx = render_compositional_context(_truster(), "flashLoan")
        assert "<compositional_context>" in ctx

    def test_unrelated(self):
        assert render_compositional_context(_truster(), "totalSupply") == ""

    def test_xml_well_formed(self):
        ctx = render_compositional_context(_truster(), "approve")
        if ctx:
            import xml.etree.ElementTree as ET
            ET.fromstring(ctx)

    def test_none(self):
        assert render_compositional_context(None, "x") == ""

    def test_risk_reason(self):
        ctx = render_compositional_context(_truster(), "approve")
        assert "<risk_reason>" in ctx


# === 4. SCOPE FILTERING ===
class TestScope:
    def _f(self, name, container, ftype="function"):
        return {"name": name, "body": "{x}", "container": container, "type": ftype}

    def test_stem_match(self):
        k, e = scope_functions_to_primary_contract(
            [self._f("foo", "contract Foo"), self._f("bar", "contract Bar")], "Foo")
        assert len(k) == 1 and k[0]["name"] == "foo" and "bar" in e

    def test_single(self):
        k, _ = scope_functions_to_primary_contract([self._f("foo", "contract Foo")], "Other")
        assert len(k) == 1

    def test_blocklist(self):
        k, _ = scope_functions_to_primary_contract([
            self._f("f", "contract TrusterLenderPool"),
            self._f("s", "contract SafeMath"),
            self._f("g", "contract ReentrancyGuard")], "Contract")
        assert len(k) == 1 and k[0]["name"] == "f"

    def test_dvt(self):
        k, _ = scope_functions_to_primary_contract([
            self._f("fl", "contract TrusterLenderPool"),
            self._f("tr", "contract DamnValuableToken")], "Contract")
        assert len(k) == 1 and k[0]["name"] == "fl"

    def test_constructor(self):
        k, e = scope_functions_to_primary_contract([
            self._f("constructor", "contract Foo", "constructor"),
            self._f("doStuff", "contract Foo")], "Foo")
        assert len(k) == 1 and k[0]["name"] == "doStuff" and "constructor" in e

    def test_modifier(self):
        k, _ = scope_functions_to_primary_contract([
            self._f("nr", "contract Foo", "modifier"),
            self._f("do", "contract Foo")], "Foo")
        assert len(k) == 1 and k[0]["name"] == "do"

    def test_fallback(self):
        k, _ = scope_functions_to_primary_contract([
            self._f("fb", "contract Foo", "fallback_receive"),
            self._f("do", "contract Foo")], "Foo")
        assert len(k) == 1 and k[0]["name"] == "do"

    def test_no_containers(self):
        k, e = scope_functions_to_primary_contract([self._f("foo", "")], "X")
        assert len(k) == 1 and e == []

    def test_empty(self):
        assert scope_functions_to_primary_contract([], "X") == ([], [])

    def test_largest(self):
        fs = [self._f(f"f{i}", "contract A") for i in range(3)]
        fs.append(self._f("g", "contract B"))
        k, _ = scope_functions_to_primary_contract(fs, "Other")
        assert len(k) == 3 and all(f["container"] == "contract A" for f in k)

    def test_type_missing(self):
        k, _ = scope_functions_to_primary_contract(
            [{"name": "foo", "body": "{x}", "container": "contract Foo"}], "Foo")
        assert len(k) == 1


