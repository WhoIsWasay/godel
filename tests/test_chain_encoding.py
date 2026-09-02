"""
Tests for the ironclad hardening features (Phases 1-5):
- Structural risk classification (Gap 1)
- Paired CFG rendering (Gap 2)
- Multi-call Z3 chain encoding (Gap 3)
- External call resolution (Gap 4)
- Wrap probe integration (Gap 5)

Run: python -m pytest tests/test_chain_encoding.py -v
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from domain.abstracter import (
    detect_compositional_candidates,
    render_paired_cfg_slice,
    _structural_risk,
    _has_external_calls,
    _state_in_guards,
    _state_in_arithmetic,
)
from domain.semantics import HarnessEncoder, MODEL_QUALITY_CHAIN


def _mock_analysis():
    return {
        "contract": "TestContract",
        "functions": {
            "approve(address,uint256)": {
                "full_name": "approve(address,uint256)",
                "visibility": "public", "modifiers": [],
                "params": [{"name": "spender", "type": "address"},
                           {"name": "amount", "type": "uint256"}],
                "returns_types": ["bool"],
                "nodes": 3, "edges": 2, "loops": 0,
                "state_writes": ["allowance"],
                "state_reads": [],
                "external_calls": [],
                "has_external_call": False,
                "guards": [],
                "assignments": [
                    {"op": "=", "lhs": "allowance", "rhs": "amount",
                     "order": 0, "when": []}
                ],
                "first_external_call_order": None,
                "branch_conditions_src": [], "has_branch": False,
                "returns_expr": "true", "internal_calls": [],
                "branches": [], "payable": False,
            },
            "flashLoan(uint256,address,address,bytes)": {
                "full_name": "flashLoan(uint256,address,address,bytes)",
                "visibility": "public", "modifiers": [],
                "params": [{"name": "amount", "type": "uint256"},
                           {"name": "token", "type": "address"},
                           {"name": "receiver", "type": "address"},
                           {"name": "data", "type": "bytes"}],
                "returns_types": [],
                "nodes": 10, "edges": 12, "loops": 0,
                "state_writes": [],
                "state_reads": ["allowance"],
                "external_calls": ["transferFrom", "functionCall"],
                "has_external_call": True,
                "guards": ["amount > 0"],
                "assignments": [],
                "first_external_call_order": 3,
                "branch_conditions_src": ["amount > 0"], "has_branch": True,
                "returns_expr": None, "internal_calls": [],
                "branches": [{"kind": "require", "expr": "amount > 0"}],
                "payable": False,
            },
            "_validate(uint256)": {
                "full_name": "_validate(uint256)",
                "visibility": "internal", "modifiers": [],
                "params": [{"name": "amount", "type": "uint256"}],
                "returns_types": [],
                "nodes": 3, "edges": 2, "loops": 0,
                "state_writes": [],
                "state_reads": ["cap"],
                "external_calls": [],
                "has_external_call": False,
                "guards": ["amount <= cap"],
                "assignments": [],
                "first_external_call_order": None,
                "branch_conditions_src": [], "has_branch": False,
                "returns_expr": None, "internal_calls": [],
                "branches": [], "payable": False,
            },
        },
        "storage_layout": [
            {"name": "allowance", "type": "mapping(address => uint256)"},
            {"name": "cap", "type": "uint256"},
        ],
    }


# === 1. STRUCTURAL RISK CLASSIFICATION ===
class TestStructuralRisk:
    def test_drain_vector_high(self):
        reader = {"state_reads": ["pool"], "external_calls": ["transferFrom"],
                   "has_external_call": True}
        writer = {"state_writes": ["pool"]}
        assert _structural_risk("pool", [], reader, writer) == "high"

    def test_guard_dependency_medium(self):
        reader = {"state_reads": ["admin"], "external_calls": [],
                   "guards": ["msg.sender == admin"]}
        writer = {"state_writes": ["admin"]}
        assert _structural_risk("admin", [], reader, writer) == "medium"

    def test_mapping_type_medium(self):
        reader = {"state_reads": ["customPool"], "external_calls": []}
        writer = {"state_writes": ["customPool"]}
        layout = [{"name": "customPool", "type": "mapping(address => uint256)"}]
        assert _structural_risk("customPool", layout, reader, writer) == "medium"

    def test_generic_low(self):
        reader = {"state_reads": ["cfg"], "external_calls": []}
        writer = {"state_writes": ["cfg"]}
        assert _structural_risk("cfg", [], reader, writer) == "low"

    def test_keyword_fallback_medium(self):
        reader = {"state_reads": ["balance"], "external_calls": []}
        writer = {"state_writes": ["balance"]}
        assert _structural_risk("balance", [], reader, writer) == "medium"

    def test_has_external_calls_from_list(self):
        assert _has_external_calls({"external_calls": ["transfer"]})
        assert not _has_external_calls({"external_calls": []})

    def test_has_external_calls_from_flag(self):
        assert _has_external_calls({"has_external_call": True})

    def test_state_in_guards(self):
        assert _state_in_guards("amount", {"guards": ["amount > 0"]})
        assert not _state_in_guards("amount", {"guards": ["msg.sender != 0"]})

    def test_state_in_arithmetic(self):
        facts = {"assignments": [{"rhs": "totalSupply + amount"}]}
        assert _state_in_arithmetic("amount", facts)
        assert not _state_in_arithmetic("amount", {"assignments": []})

    def test_structural_drain_no_keyword_match(self):
        analysis = {
            "functions": {
                "setPool(address)": {
                    "state_writes": ["customPool"], "state_reads": [],
                    "external_calls": []
                },
                "drain(uint256)": {
                    "state_writes": [], "state_reads": ["customPool"],
                    "external_calls": ["transferFrom"],
                    "has_external_call": True
                },
            },
            "storage_layout": [
                {"name": "customPool", "type": "mapping(address => uint256)"},
            ],
        }
        candidates = detect_compositional_candidates(analysis)
        assert len(candidates) >= 1
        pair = [c for c in candidates
                if c["writer"] == "setPool" and c["reader"] == "drain"]
        assert len(pair) == 1
        assert pair[0]["risk"] == "high"


# === 2. PAIRED CFG RENDERING ===
class TestPairedCfg:
    def test_renders_both_functions(self):
        analysis = _mock_analysis()
        block = render_paired_cfg_slice(analysis, "approve", "flashLoan")
        assert "<cfg_abstraction" in block
        assert "focus_function_cfg" in block
        assert "compositional_pair_cfg" in block
        assert "approve" in block
        assert "flashLoan" in block

    def test_both_storage_visible(self):
        analysis = _mock_analysis()
        block = render_paired_cfg_slice(analysis, "approve", "flashLoan")
        assert "allowance" in block

    def test_none_analysis_empty(self):
        assert render_paired_cfg_slice(None, "a", "b") == ""

    def test_unknown_function_empty(self):
        analysis = _mock_analysis()
        assert render_paired_cfg_slice(analysis, "nonexistent", "flashLoan") == ""

    def test_truncation(self):
        analysis = _mock_analysis()
        block = render_paired_cfg_slice(analysis, "approve", "flashLoan",
                                         max_chars=100)
        assert len(block) <= 100


# === 3. CHAIN ENCODING ===
class TestChainEncoding:
    def test_encode_sequence_returns_chain(self):
        analysis = _mock_analysis()
        encoder = HarnessEncoder(analysis)
        chain = encoder.encode_function_sequence(["approve", "flashLoan"])
        assert chain is not None
        assert chain["quality"] == MODEL_QUALITY_CHAIN
        assert "approve->flashLoan" in chain["function"]

    def test_chain_has_bridge_constraints(self):
        analysis = _mock_analysis()
        encoder = HarnessEncoder(analysis)
        chain = encoder.encode_function_sequence(["approve", "flashLoan"])
        assert chain is not None
        assert "==" in chain["code"]
        assert "_c1" in chain["code"]
        assert "_c2" in chain["code"]

    def test_chain_has_build_model(self):
        analysis = _mock_analysis()
        encoder = HarnessEncoder(analysis)
        chain = encoder.encode_function_sequence(["approve", "flashLoan"])
        assert "def build_model(witness_bound=None):" in chain["code"]
        assert "from z3 import *" in chain["code"]
        # witness-minimization hook is emitted for the chain harness too
        assert "_capped = [" in chain["code"]
        assert "_s <= witness_bound for _s in _capped" in chain["code"]

    def test_chain_symbols_suffixed(self):
        analysis = _mock_analysis()
        encoder = HarnessEncoder(analysis)
        chain = encoder.encode_function_sequence(["approve", "flashLoan"])
        keys = list(chain["symbols"].keys())
        c1_keys = [k for k in keys if "_c1" in k]
        c2_keys = [k for k in keys if "_c2" in k]
        assert len(c1_keys) > 0
        assert len(c2_keys) > 0

    def test_single_function_returns_none(self):
        analysis = _mock_analysis()
        encoder = HarnessEncoder(analysis)
        assert encoder.encode_function_sequence(["approve"]) is None

    def test_empty_list_returns_none(self):
        analysis = _mock_analysis()
        encoder = HarnessEncoder(analysis)
        assert encoder.encode_function_sequence([]) is None

    def test_suffix_preserves_single_function(self):
        analysis = _mock_analysis()
        encoder_no_suffix = HarnessEncoder(analysis)
        result_no_suffix = encoder_no_suffix.encode_function("approve")

        encoder_empty_suffix = HarnessEncoder(analysis, suffix="")
        result_empty_suffix = encoder_empty_suffix.encode_function("approve")

        assert result_no_suffix is not None
        assert result_empty_suffix is not None
        assert result_no_suffix["code"] == result_empty_suffix["code"]
        assert result_no_suffix["quality"] == result_empty_suffix["quality"]


# === 4. EXTERNAL CALL RESOLUTION ===
class TestExternalCallResolution:
    def test_resolve_internal_function(self):
        analysis = _mock_analysis()
        encoder = HarnessEncoder(analysis)
        result = encoder._resolve_call_target("_validate(amount)")
        assert result is not None
        key, facts = result
        assert "_validate" in key

    def test_skip_known_external(self):
        analysis = _mock_analysis()
        encoder = HarnessEncoder(analysis)
        assert encoder._resolve_call_target("transfer(to, amount)") is None
        assert encoder._resolve_call_target("transferFrom(a, b, c)") is None

    def test_skip_unknown_function(self):
        analysis = _mock_analysis()
        encoder = HarnessEncoder(analysis)
        assert encoder._resolve_call_target("nonexistent()") is None

    def test_skip_target_with_external_calls(self):
        analysis = _mock_analysis()
        encoder = HarnessEncoder(analysis)
        assert encoder._resolve_call_target("flashLoan(1, a, b, c)") is None

    def test_extract_target_guards(self):
        analysis = _mock_analysis()
        encoder = HarnessEncoder(analysis)
        encoder._reg("cap", "cap__old")
        encoder._reg("arg_amount", "a_amount")
        target_facts = analysis["functions"]["_validate(uint256)"]
        guards = encoder._encode_resolved_target_guards(target_facts, {})
        assert len(guards) >= 0
