"""
Dry-run test for compositional vulnerability detection.

Verifies that the abstracter correctly identifies cross-function
state flow patterns like approve-then-drain in TrusterLenderPool.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from domain.abstracter import detect_compositional_candidates, render_compositional_context


def _mock_analysis():
    return {
        "contract": "TrusterLenderPool",
        "functions": {
            "approve(address,uint256)": {
                "state_writes": ["allowance"],
                "state_reads": [],
                "external_calls": [],
                "internal_calls": [],
            },
            "flashLoan(uint256,address,address,bytes)": {
                "state_writes": [],
                "state_reads": ["allowance"],
                "external_calls": ["transferFrom", "functionCall"],
                "internal_calls": [],
            },
            "withdraw(uint256)": {
                "state_writes": [],
                "state_reads": ["balance"],
                "external_calls": ["transfer"],
                "internal_calls": [],
            },
        },
    }


def test_compositional_detects_approve_flashloan_pair():
    candidates = detect_compositional_candidates(_mock_analysis())
    assert len(candidates) > 0

    pair = [c for c in candidates
            if {c["writer"], c["reader"]} == {"approve", "flashLoan"}]
    assert len(pair) == 1
    p = pair[0]
    assert p["risk"] == "high"
    assert "allowance" in p["shared_state"]


def test_compositional_context_renders_for_both_sides():
    analysis = _mock_analysis()

    ctx_a = render_compositional_context(analysis, "approve")
    assert "<compositional_context>" in ctx_a
    assert "allowance" in ctx_a

    ctx_f = render_compositional_context(analysis, "flashLoan")
    assert "<compositional_context>" in ctx_f
    assert "allowance" in ctx_f


def test_compositional_context_empty_for_unrelated_function():
    analysis = _mock_analysis()
    ctx = render_compositional_context(analysis, "withdraw")
    assert ctx == ""


def test_compositional_handles_none_analysis():
    assert detect_compositional_candidates(None) == []
    assert render_compositional_context(None, "foo") == ""


def test_compositional_handles_no_shared_state():
    analysis = {
        "functions": {
            "foo()": {"state_writes": ["x"], "state_reads": []},
            "bar()": {"state_writes": ["y"], "state_reads": []},
        }
    }
    assert detect_compositional_candidates(analysis) == []
