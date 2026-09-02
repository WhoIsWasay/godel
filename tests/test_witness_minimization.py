"""Tests for the harness-composition + Z3 witness-minimization fix.

Root cause addressed
--------------------
The deterministic harness (``build_model``) was NEVER composed into the executed
property script (``compose_script`` was dead code in the pipeline). The specifier
returns the property block alone (``solver, V = build_model()``), so the first
``run_z3`` always raised ``NameError: build_model`` and CEGIS burned an LLM
repair call to improvise a standalone model with full uint256 bounds. That
improvised model produced huge witnesses (~2**254); the Forge PoC hardcoded them
as uint256 constants and its own ``assets * totalSupply`` overflowed -> setUp
reverted -> harness_error -> a REAL bug (MiniVault deposit zero-share minting)
was demoted to INFORMATIONAL.

Part 1: ``executor_node`` composes harness+property before running (guarding
        against double-compose when the LLM already echoed ``def build_model``).
Part 2: ``build_model(witness_bound=N)`` + a post-SAT tight->loose re-solve
        ladder shrinks a huge witness to a groundable one. Fallback keeps the
        original witness when the bug needs large magnitude, so the Phase-1
        verdict NEVER changes.

Run: python -m pytest tests/test_witness_minimization.py -v
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from domain import config
from domain.semantics import HarnessEncoder, compose_script
from domain.cegis import CEGIS, _inject_witness_bound

z3 = pytest.importorskip("z3")  # real solver; whole module skips if unavailable
from domain.z3_runner import run_z3  # noqa: E402


def _deposit_analysis():
    """Minimal static-analysis facts for a deposit() with a floor-division
    share computation — the shape that triggered the huge-witness bug."""
    return {
        "contract": "MiniVault",
        "storage_layout": [
            {"name": "totalSupply", "type": "uint256"},
            {"name": "totalAssets", "type": "uint256"},
        ],
        "functions": {
            "deposit(uint256)": {
                "params": [{"name": "assets", "type": "uint256"}],
                "guards": [{"text": "assets > 0", "when": []}],
                "assignments": [
                    {"op": "=", "lhs": "shares",
                     "rhs": "(assets * totalSupply) / totalAssets",
                     "order": 1, "when": []},
                ],
                "loops": [],
                "has_external_call": False,
                "external_calls": [],
                "first_external_call_order": None,
            }
        },
    }


# Floor-division violation: a SMALL witness exists (assets=1, supply=1, total=2).
DEPOSIT_PROPERTY = """from z3 import *

solver, V = build_model()

solver.push()
print("SANITY:", solver.check())
solver.pop()

solver.add(V['arg_assets'] > 0)
solver.add(V['totalSupply'] > 0)
solver.add(V['totalAssets'] > 0)
solver.add((V['arg_assets'] * V['totalSupply']) / V['totalAssets'] == 0)

if solver.check() == sat:
    print("BUG FOUND:", solver.model())
else:
    print("Property holds")
"""

# Overflow-class violation: ONLY a huge witness exists (assets > 2**200), so the
# minimization ladder must fall back and keep the original full-range model.
OVERFLOW_PROPERTY = """from z3 import *

solver, V = build_model()

solver.push()
print("SANITY:", solver.check())
solver.pop()

solver.add(V['arg_assets'] > 2**200)

if solver.check() == sat:
    print("BUG FOUND:", solver.model())
else:
    print("Property holds")
"""


def _harness():
    return HarnessEncoder(_deposit_analysis()).encode_function("deposit")


def _max_abs(cex):
    vals = (cex or {}).get("assignments", {}).values()
    return max((abs(v) for v in vals), default=0)


# --------------------------------------------------------------- Part 2: emit
def test_build_model_signature_has_witness_bound():
    code = _harness()["code"]
    assert "def build_model(witness_bound=None):" in code
    assert "_capped = [" in code
    assert "if witness_bound is not None:" in code
    assert "_s <= witness_bound for _s in _capped" in code


def test_inject_witness_bound_rewrites_call_not_def():
    composed = compose_script(_harness(), DEPOSIT_PROPERTY)
    injected = _inject_witness_bound(composed, 10**6)
    assert injected != composed
    # the property's zero-arg call is rewritten ...
    assert "build_model(witness_bound=1000000)" in injected
    # ... but the harness DEFINITION (non-empty parens) is left intact.
    assert "def build_model(witness_bound=None):" in injected
    assert injected.count("def build_model") == 1


def test_inject_witness_bound_noop_without_call():
    assert _inject_witness_bound("x = 1\nprint(x)", 5) == "x = 1\nprint(x)"


# ------------------------------------------- Part 1: composition fixes magnitude
def test_composed_primary_solve_is_sat_and_small():
    """With the harness actually composed, Z3 returns a tiny groundable witness
    (not ~2**254). This is the core of the deposit-bug fix."""
    composed = compose_script(_harness(), DEPOSIT_PROPERTY)
    res = run_z3(composed, strict=True)
    assert res["status"] == "sat", res.get("error")
    cex = CEGIS.extract_counterexample(res["output"])
    assert _max_abs(cex) <= config.WITNESS_GROUNDABLE_MAX
    # products of two such values cannot overflow uint256 in the PoC
    assert _max_abs(cex) ** 2 < 2**256


# ------------------------------------------------- Part 2: minimization ladder
def test_minimize_skips_standalone_script():
    """No build_model hook -> nothing to inject -> keep original (no re-solve)."""
    calls = []
    ceg = CEGIS(agent=None, run_z3_tool=lambda c: calls.append(c) or {"status": "sat"})
    out = ceg._minimize_witness(
        "from z3 import *\nsolver = Solver()",
        {"assignments": {"x": 2**250}}, [],
    )
    assert out is None
    assert calls == []


def test_minimize_skips_when_already_small():
    """A groundable witness must not trigger any extra Z3 re-solve."""
    calls = []
    ceg = CEGIS(agent=None, run_z3_tool=lambda c: calls.append(c) or {"status": "sat"})
    composed = compose_script(_harness(), DEPOSIT_PROPERTY)
    out = ceg._minimize_witness(composed, {"assignments": {"a_assets": 1}}, [])
    assert out is None
    assert calls == []


def test_minimize_shrinks_huge_witness():
    """Huge cex presented, but a small witness exists -> first rung wins."""
    ceg = CEGIS(agent=None, run_z3_tool=lambda c: run_z3(c, strict=True))
    composed = compose_script(_harness(), DEPOSIT_PROPERTY)
    huge = {"assignments": {"a_assets": 2**250, "totalSupply__old": 2**240,
                            "totalAssets__old": 2**251}}
    attempts = []
    out = ceg._minimize_witness(composed, huge, attempts)
    assert out is not None and out["status"] == "sat"
    assert out["witness_minimized"] is True
    assert out["witness_bound"] == config.WITNESS_MINIMIZE_BOUNDS[0]
    shrunk = CEGIS.extract_counterexample(out["output"])
    assert _max_abs(shrunk) <= config.WITNESS_MINIMIZE_BOUNDS[0]
    assert attempts and attempts[0]["phase"] == "minimize"


def test_minimize_falls_back_when_only_huge_witness():
    """Overflow-class bug: every rung UNSAT -> keep the original huge witness.
    The verdict (SAT) is preserved — minimization never fabricates a UNSAT."""
    ceg = CEGIS(agent=None, run_z3_tool=lambda c: run_z3(c, strict=True))
    composed = compose_script(_harness(), OVERFLOW_PROPERTY)
    primary = run_z3(composed, strict=True)
    assert primary["status"] == "sat"
    cex = CEGIS.extract_counterexample(primary["output"])
    assert _max_abs(cex) > 2**200
    attempts = []
    out = ceg._minimize_witness(composed, cex, attempts)
    assert out is None  # no smaller witness -> caller keeps the original
    # every rung was tried and came back unsat
    assert len(attempts) == len(config.WITNESS_MINIMIZE_BOUNDS)
    assert all(a["status"] == "unsat" for a in attempts)


# ------------------------------------------- Part 3: Z3-timeout rescue ladder
def test_timeout_bound_rescues_unbounded_timeout():
    """An unbounded nonlinear property times out; capping the harness symbols
    makes it decidable and the FIRST rung yields a SAT witness — no LLM repair."""
    calls = []

    def _fake(code):
        calls.append(code)
        if "witness_bound=" in code:
            return {"status": "sat", "output": "BUG FOUND: [a_assets = 1]",
                    "z3_code": code}
        return {"status": "error", "output": None,
                "error": "Z3 timeout (30.0s)", "z3_code": code}

    ceg = CEGIS(agent=None, run_z3_tool=_fake)
    composed = compose_script(_harness(), DEPOSIT_PROPERTY)
    attempts = []
    out = ceg._retry_with_witness_bound(composed, attempts)
    assert out is not None and out["status"] == "sat"
    assert out["timeout_bounded"] is True
    assert out["witness_bound"] == config.WITNESS_TIMEOUT_BOUNDS[0]
    # only the first (smallest) rung was needed before SAT
    assert len(calls) == 1 and "witness_bound=" in calls[0]
    assert attempts and attempts[0]["phase"] == "timeout_bound"


def test_timeout_bound_noop_without_build_model():
    """A standalone / LLM-improvised script has no build_model hook to inject
    into -> None, and no Z3 re-solve is attempted."""
    calls = []
    ceg = CEGIS(agent=None, run_z3_tool=lambda c: calls.append(c) or {"status": "sat"})
    out = ceg._retry_with_witness_bound("from z3 import *\nsolver = Solver()", [])
    assert out is None
    assert calls == []


def test_timeout_bound_returns_none_when_all_rungs_unsat():
    """Overflow-class bug: every bounded rung is UNSAT. A bounded UNSAT is NOT a
    safety proof (the violation may need magnitude above the cap), so None is
    returned to fall through — a verdict is never fabricated."""
    ceg = CEGIS(agent=None, run_z3_tool=lambda c: run_z3(c, strict=True))
    composed = compose_script(_harness(), OVERFLOW_PROPERTY)
    attempts = []
    out = ceg._retry_with_witness_bound(composed, attempts)
    assert out is None
    assert len(attempts) == len(config.WITNESS_TIMEOUT_BOUNDS)
    assert all(a["status"] == "unsat" for a in attempts)


def test_run_with_repair_timeout_rescued_without_llm(monkeypatch, tmp_path):
    """End-to-end: the initial run times out, the witness-bound rescue finds a
    SAT, and run_with_repair returns it WITHOUT spending any LLM repair. agent is
    None, so had the loop fallen through to _repair_script it would have returned
    no code and the result would have stayed an error — proving the rescue path."""
    monkeypatch.setattr(config, "DEBUG_FOLDER", tmp_path)
    calls = []

    def _fake(code):
        calls.append(code)
        if "witness_bound=" in code:
            return {"status": "sat", "output": "BUG FOUND: [a_assets = 1]",
                    "z3_code": code}
        return {"status": "error", "output": None,
                "error": "Z3 timeout (30.0s)", "z3_code": code}

    ceg = CEGIS(agent=None, run_z3_tool=_fake)
    composed = compose_script(_harness(), DEPOSIT_PROPERTY)
    res = ceg.run_with_repair(composed, focus_function="deposit")
    assert res["status"] == "sat"
    assert res["repairs_used"] == 0                 # no LLM repair spent
    assert any("witness_bound=" in c for c in calls)  # bounded re-solve ran


# ------------------------------------------------------- Part 1: executor glue
def test_executor_composes_harness_before_running():
    from domain.graph_nodes import executor_node

    captured = {}

    class _RecordingCEGIS:
        def run_with_repair(self, z3_code, max_repairs=None, **kwargs):
            captured["code"] = z3_code
            return {"status": "sat", "output": "BUG FOUND: [a = 1]",
                    "counterexample": {"assignments": {"a": 1}},
                    "repairs_used": 0, "deterministic_repairs": 0}

    harness = _harness()
    state = {
        "z3_code": DEPOSIT_PROPERTY,           # property-only, as the specifier emits
        "iterations": 0, "executor_runs": 0,
        "current_focus_function": "deposit(uint256)",
        "semantic_harness": harness,
        "findings": [{"id": 1}],
    }
    executor_node(state, _RecordingCEGIS())
    ran = captured["code"]
    # the executed script now DEFINES build_model (harness composed in) ...
    assert "def build_model(witness_bound=None):" in ran
    # ... exactly once (no double-compose), and still carries the property.
    assert ran.count("def build_model") == 1
    assert "BUG FOUND:" in ran
    # state["z3_code"] is untouched so proof.py stays the readable property.
    assert state["z3_code"] == DEPOSIT_PROPERTY


def test_executor_does_not_double_compose():
    from domain.graph_nodes import executor_node

    captured = {}

    class _RecordingCEGIS:
        def run_with_repair(self, z3_code, max_repairs=None, **kwargs):
            captured["code"] = z3_code
            return {"status": "sat", "output": "BUG FOUND: [a = 1]",
                    "counterexample": {"assignments": {"a": 1}},
                    "repairs_used": 0, "deterministic_repairs": 0}

    harness = _harness()
    already = compose_script(harness, DEPOSIT_PROPERTY)  # LLM echoed the harness
    state = {
        "z3_code": already,
        "iterations": 0, "executor_runs": 0,
        "current_focus_function": "deposit(uint256)",
        "semantic_harness": harness,
        "findings": [{"id": 1}],
    }
    executor_node(state, _RecordingCEGIS())
    assert captured["code"] == already            # passed through unchanged
    assert captured["code"].count("def build_model") == 1
