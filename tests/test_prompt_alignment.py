"""Offline prompt/code alignment tests.

These tests verify that each pipeline agent wraps its LLM inputs in the XML
tags that the corresponding prompt's <grounding_constraint> references. No
API calls are made — a MockLLM captures messages for assertion.

Run with: pytest tests/test_prompt_alignment.py -v
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


class MockResponse:
    def __init__(self, content="```solidity\nfunction x() public {}\n```"):
        self.content = content


class MockLLM:
    """Captures the last messages passed to invoke() for offline assertion."""

    def __init__(self, response_content="OK"):
        self.last_messages = None
        self._response = MockResponse(response_content)

    def invoke(self, messages, **kwargs):
        self.last_messages = messages
        return self._response


def _get_user_content(messages) -> str:
    for msg in messages:
        if type(msg).__name__ == "HumanMessage":
            return msg.content
    return ""


def _get_system_content(messages) -> str:
    for msg in messages:
        if type(msg).__name__ == "SystemMessage":
            return msg.content
    return ""


# --------------------------------------------------------------------- FIXER

def test_fixer_wraps_xml_tags():
    from domain.fixer import FixerAgent

    mock = MockLLM(response_content="```solidity\nfunction fixed() public {}\n```")
    agent = FixerAgent(mock)

    finding = {
        "target_function": "deposit",
        "intent": "floor division can mint zero shares",
        "constraint": "shares > 0 when amount > 0",
        "relevant_code": "shares = amount * totalSupply / totalAssets;",
    }
    state = {
        "user_contract": "contract Vault { mapping(address=>uint) shares; }",
        "bug_report": "[Z3] Counterexample: amount=1, totalAssets=500000",
    }

    result = agent.generate_remediation(finding, state)

    assert mock.last_messages is not None, "Fixer did not invoke LLM"
    user = _get_user_content(mock.last_messages)
    system = _get_system_content(mock.last_messages)

    # Grounding_constraint references these 3 tags — all must appear as open+close pairs
    for tag in ("full_contract_context", "vulnerable_code_boundary", "solver_counterexample_trace"):
        assert f"<{tag}>" in user, f"Fixer user message missing <{tag}> open tag"
        assert f"</{tag}>" in user, f"Fixer user message missing </{tag}> close tag"

    # Payloads must be non-empty
    assert "contract Vault" in user
    assert "shares = amount * totalSupply / totalAssets" in user
    assert "Counterexample" in user

    # Finding metadata section
    assert "<function_name>deposit</function_name>" in user

    # System prompt loaded from file
    assert "Remediation-Fixer" in system or "fix" in system.lower()
    assert result  # returned something non-empty


# --------------------------------------------------------- PROPERTY GENERATOR

def test_propertygenerator_wraps_xml_tags():
    from domain.propertygenerator import PropertyGenerator
    from unittest.mock import patch

    mock = MockLLM(response_content="```python\nfrom z3 import *\ns = Solver()\n```")
    gen = PropertyGenerator(mock)

    # Mock call_with_retry to pass through to the mock LLM directly
    with patch("domain.propertygenerator.call_with_retry", side_effect=lambda fn: fn()):
        gen.build_prompt(
            expansion={"intent": "shares must be > 0 when deposit > 0", "queries": []},
            contract="contract Vault { function deposit(uint amount) public {} }",
            findings=[],
            semantic_harness=None,
        )
        gen.propertyGeneration()

    assert mock.last_messages is not None
    user = _get_user_content(mock.last_messages)

    for tag in ("intent", "contract", "findings"):
        assert f"<{tag}>" in user, f"PropertyGenerator user message missing <{tag}>"
        assert f"</{tag}>" in user, f"PropertyGenerator user message missing </{tag}>"

    assert "contract Vault" in user
    assert "shares must be > 0" in user


# ------------------------------------------- SPECIFIER GROUNDING (warm-seeded)
# The specifier used to pass ONLY finding['intent'] into build_prompt, dropping
# the invariant (constraint/relevant_code) and the human's concrete
# counterexample — the exact grounding a warm-seeded MCP re-confirm supplies.
# These lock in that all of it now reaches the prompt.

def test_grounded_intent_folds_all_fields():
    from domain.graph_nodes import _grounded_intent
    out = _grounded_intent({
        "intent": "base intent",
        "constraint": "shares = (assets * totalSupply) / totalAssets truncates to 0",
        "relevant_code": "assets > 0 => shares > 0 (Anti-Dilution)",
        "counterexample": {"assets": 1, "totalSupply": 1, "totalAssets": 1000},
    })
    assert "base intent" in out
    assert "truncates to 0" in out            # constraint / root cause
    assert "Anti-Dilution" in out             # invariant / relevant_code
    assert '"totalAssets": 1000' in out       # concrete witness, JSON-encoded


def test_grounded_intent_no_extras_is_just_intent():
    from domain.graph_nodes import _grounded_intent
    assert _grounded_intent({"intent": "only this"}) == "only this"
    assert _grounded_intent({}) == ""


def test_specifier_feeds_invariant_and_witness_into_prompt(monkeypatch):
    from domain.graph_nodes import specifier_node
    from domain.propertygenerator import PropertyGenerator
    from unittest.mock import patch

    # RAG must not touch the network in a unit test.
    monkeypatch.setattr("domain.rag.retrieve_findings_for_specifier",
                        lambda *a, **k: ([], {}))

    mock = MockLLM(response_content="```python\nfrom z3 import *\nsolver, V = build_model()\n```")
    gen = PropertyGenerator(mock)
    state = {
        "user_contract": "contract MiniVault { function deposit(uint256 assets) external {} }",
        "findings": [{
            "target_function": "deposit",
            "intent": "A non-zero deposit can mint zero shares.",
            "constraint": "shares = (assets * totalSupply) / totalAssets truncates to 0",
            "relevant_code": "assets > 0 => shares > 0 (Anti-Dilution, Invariant 1)",
            "counterexample": {"assets": 1, "totalSupply": 1, "totalAssets": 1000},
        }],
        "semantic_harness": None,
        "supervisor_critique": None,
    }

    with patch("domain.propertygenerator.call_with_retry", side_effect=lambda fn: fn()):
        specifier_node(state, gen)

    user = _get_user_content(mock.last_messages)
    assert "Anti-Dilution" in user            # invariant reached the prompt
    assert "truncates to 0" in user           # root cause reached the prompt
    assert "1000" in user                     # concrete witness reached the prompt


# ---------------------------------------------------------------- SUPERVISOR

def test_supervisor_wraps_xml_tags():
    from domain.graph_nodes import supervisor_node
    from unittest.mock import patch

    mock = MockLLM(response_content='{"thought_process": "ok", "status": "APPROVED", "supervisor_critique": null}')

    state = {
        "current_focus_function": "deposit",
        "findings": [{"id": 1, "intent": "zero shares", "target_function": "deposit"}],
        "user_contract": "contract Vault { function deposit(uint a) public {} }",
        "supervisor_runs": 0,
    }

    with patch("domain.graph_nodes.call_with_retry", side_effect=lambda fn: fn()):
        result = supervisor_node(state, mock)

    assert mock.last_messages is not None
    user = _get_user_content(mock.last_messages)

    for tag in ("findings", "contract"):
        assert f"<{tag}>" in user, f"Supervisor user message missing <{tag}>"
        assert f"</{tag}>" in user, f"Supervisor user message missing </{tag}>"

    assert "contract Vault" in user
    assert "zero shares" in user
    assert result["supervisor_critique"] is None  # APPROVED path


# ----------------------------------------------------------------- VERIFIER

def test_verifier_wraps_xml_tags():
    from domain.verifier import PropertyVerifierAgent
    from unittest.mock import patch

    mock = MockLLM(response_content="```solidity\ncontract Test {}\n```")
    verifier = PropertyVerifierAgent(mock)

    finding = {"target_function": "deposit"}
    state = {"z3_result": {"status": "sat", "output": "BUG FOUND: x=1"}, "mode": "standard"}

    with patch("domain.verifier.call_with_retry", side_effect=lambda fn: fn()):
        verifier.generate_test_suite(
            finding, state,
            contract_code="contract Vault { function deposit(uint a) public {} }",
            contract_filename="Vault.sol",
        )

    assert mock.last_messages is not None

    # ChatPromptTemplate.format_messages returns [(SystemMessage, ...), (HumanMessage, ...)]
    # Extract the user message (last in the list)
    user_content = ""
    system_content = ""
    for msg in mock.last_messages:
        t = type(msg).__name__
        if t == "HumanMessage":
            user_content = msg.content
        elif t == "SystemMessage":
            system_content = msg.content

    for tag in ("contract", "solver_trace"):
        assert f"<{tag}>" in user_content, f"Verifier user message missing <{tag}>"
        assert f"</{tag}>" in user_content, f"Verifier user message missing </{tag}>"

    assert "contract Vault" in user_content
    assert "deposit" in user_content
    assert "Vault.sol" in user_content

    # System prompt should be loaded from verifier_prompt.txt (stronger file)
    assert "Property-Verifier" in system_content or "verification_engineer_directive" in system_content


# ------------------------------------------------------- DEAD FILE REMOVED

def test_inspector_prompt_file_removed():
    """inspector_prompt.txt was dead code and has been deleted."""
    from domain.config import PROMPTS_DIR
    assert not (PROMPTS_DIR / "inspector_prompt.txt").exists(), \
        "prompts/inspector_prompt.txt should have been deleted (dead file)"


# ---------------------------------------------- SYSTEM PROMPT FILE LOADED

def test_fixer_system_prompt_loaded_from_file():
    """Fixer must load fixer_prompt.txt as system prompt, not an empty string."""
    from domain.fixer import FixerAgent

    mock = MockLLM()
    agent = FixerAgent(mock)

    assert agent.system_prompt, "Fixer system prompt is empty"
    assert "Remediation-Fixer" in agent.system_prompt or "fix" in agent.system_prompt.lower()


def test_verifier_system_prompt_loaded_from_file():
    """Verifier must load verifier_prompt.txt (or fall back to inline)."""
    from domain.verifier import _load_verifier_system_prompt

    prompt = _load_verifier_system_prompt()
    assert prompt, "Verifier system prompt is empty"
    # Should contain one of the known identity markers from either source
    assert "Property-Verifier" in prompt or "verification_engineer_directive" in prompt
