"""tests/test_z3_deterministic_repair.py — offline tests for the
deterministic (LLM-free) Z3 repair layer added to kill the dominant
first-attempt failure class (NameError from made-up/bare symbols).

Covers:
  * domain/z3_repair.py — introspection, matching, substitution, preflight,
    persistence.
  * domain/cegis.py    — layered repair: preflight first, deterministic
    NameError fix before LLM, LLM fallback only for real semantic errors,
    bounded budgets, repair-log persistence.
"""
import json

import pytest

from domain import z3_repair
from domain.z3_repair import (
    best_match,
    extract_missing_name,
    is_harness_mode,
    module_scope_names,
    persist_repair_log,
    preflight_fix,
    repair_name_error,
    static_undefined_names,
    v_symbol_keys,
    _sub_identifier,
)


# ---------------------------------------------------------------------------
# Sample scripts
# ---------------------------------------------------------------------------

HARNESS_SCRIPT = '''from z3 import *

def build_model():
    totalSupply = Int('totalSupply')
    shares = Int('shares')
    bounds = [totalSupply >= 0, totalSupply <= 1000, shares >= 0]
    solver = Solver()
    solver.add(bounds)
    V = {'totalSupply': totalSupply, 'totalShares': shares}
    return solver, V

solver, V = build_model()
attacker = Int('attacker')
solver.add(attacker >= 0)
solver.add(totalSuply + attacker > 1000)   # typo: bare name, not in V either
if solver.check() == sat:
    print("BUG FOUND: overflow")
else:
    print("Property holds")
'''

STANDALONE_SCRIPT = '''from z3 import *

balance = Int('balance')
withdrawAmount = Int('withdrawAmount')
s = Solver()
s.add(balance >= 0, balance <= 100)
s.add(withdrawAmount > balence)            # typo of own var
if s.check() == sat:
    print("BUG FOUND: over-withdraw")
else:
    print("Property holds")
'''

CLEAN_SCRIPT = '''from z3 import *

x = Int('x')
s = Solver()
s.add(x > 0, x < 5)
print("SANITY:", s.check())
if s.check() == sat:
    print("BUG FOUND: trivial")
else:
    print("Property holds")
'''


# ---------------------------------------------------------------------------
# 1. Introspection primitives
# ---------------------------------------------------------------------------

class TestIntrospection:
    def test_extract_missing_name(self):
        err = ('Traceback (most recent call last):\n  File "x.py", line 3\n'
               "NameError: name 'totalSuply' is not defined")
        assert extract_missing_name(err) == "totalSuply"

    def test_extract_missing_name_non_nameerror(self):
        assert extract_missing_name("KeyError: 'x'") is None
        assert extract_missing_name("") is None
        assert extract_missing_name(None) is None

    def test_module_scope_names_excludes_function_locals(self):
        names = module_scope_names(HARNESS_SCRIPT)
        assert "solver" in names          # rebound at module scope
        assert "V" in names
        assert "attacker" in names
        assert "build_model" in names
        # locals of build_model must NOT be offered as bare substitutions
        assert "totalSupply" not in names
        assert "shares" not in names

    def test_module_scope_names_standalone(self):
        names = module_scope_names(STANDALONE_SCRIPT)
        assert {"balance", "withdrawAmount", "s"} <= names

    def test_module_scope_names_syntax_error(self):
        assert module_scope_names("def broken(:") == set()

    def test_v_symbol_keys(self):
        keys = v_symbol_keys(HARNESS_SCRIPT)
        assert keys == {"totalSupply", "totalShares"}

    def test_is_harness_mode(self):
        assert is_harness_mode(HARNESS_SCRIPT) is True
        assert is_harness_mode(STANDALONE_SCRIPT) is False


# ---------------------------------------------------------------------------
# 2. Matching
# ---------------------------------------------------------------------------

class TestMatching:
    def test_exact_normalized_match_ignores_case_and_underscores(self):
        assert best_match("total_supply", {"totalSupply"}) == "totalSupply"
        assert best_match("TOTALSUPPLY", {"totalSupply"}) == "totalSupply"

    def test_fuzzy_match(self):
        assert best_match("totalSuply", {"totalSupply", "shares"}) == "totalSupply"
        assert best_match("balence", {"balance", "withdrawAmount"}) == "balance"

    def test_no_match_when_dissimilar(self):
        assert best_match("unicorn", {"balance", "shares"}) is None

    def test_never_returns_missing_itself(self):
        assert best_match("balance", {"balance"}) is None

    def test_empty_candidates(self):
        assert best_match("anything", set()) is None


# ---------------------------------------------------------------------------
# 3. Substitution
# ---------------------------------------------------------------------------

class TestSubstitution:
    def test_sub_skips_quoted_occurrences(self):
        code = "print('totalSupply')\ny = totalSupply + 1"
        out = _sub_identifier(code, "totalSupply", "V['totalSupply']")
        assert "print('totalSupply')" in out           # string untouched
        assert "y = V['totalSupply'] + 1" in out

    def test_sub_word_boundaries(self):
        code = "totalSupplyX = totalSupply"
        out = _sub_identifier(code, "totalSupply", "Q")
        assert out == "totalSupplyX = Q"


# ---------------------------------------------------------------------------
# 4. Deterministic NameError repair
# ---------------------------------------------------------------------------

class TestRepairNameError:
    def test_standalone_self_correction(self):
        err = "NameError: name 'balence' is not defined"
        fixed = repair_name_error(STANDALONE_SCRIPT, err)
        assert fixed is not None
        assert "withdrawAmount > balance" in fixed
        assert "balence" not in fixed

    def test_harness_bare_name_becomes_v_lookup(self):
        # `totalSuply` is undefined at module scope and near-matches V key
        err = "NameError: name 'totalSuply' is not defined"
        fixed = repair_name_error(HARNESS_SCRIPT, err)
        assert fixed is not None
        assert "V['totalSupply']" in fixed

    def test_harness_uses_known_symbols_from_state(self):
        # Script references `totalShares` bare; the generated V literal lost
        # that key, but the executor-supplied harness registry still has it.
        code = HARNESS_SCRIPT.replace("'totalShares': shares", "'other': shares")
        code = code.replace("totalSuply + attacker", "totalShares + attacker")
        err = "NameError: name 'totalShares' is not defined"
        assert repair_name_error(code, err) is None
        fixed = repair_name_error(code, err, known_symbols=["totalShares"])
        assert fixed is not None
        assert "V['totalShares']" in fixed

    def test_returns_none_without_confident_match(self):
        err = "NameError: name 'zzz_nonexistent' is not defined"
        assert repair_name_error(STANDALONE_SCRIPT, err) is None

    def test_returns_none_for_non_nameerror(self):
        assert repair_name_error(STANDALONE_SCRIPT, "KeyError: 'x'") is None

    def test_returns_none_on_empty_inputs(self):
        assert repair_name_error("", "NameError: name 'x' is not defined") is None
        assert repair_name_error(None, "NameError: name 'x' is not defined") is None


# ---------------------------------------------------------------------------
# 5. Static preflight detection
# ---------------------------------------------------------------------------

class TestStaticUndefinedNames:
    def test_flags_bare_undefined_name(self):
        assert "totalSuply" in static_undefined_names(HARNESS_SCRIPT)

    def test_does_not_flag_z3_star_imports_or_builtins(self):
        undef = static_undefined_names(CLEAN_SCRIPT)
        assert undef == set()
        undef2 = static_undefined_names(STANDALONE_SCRIPT.replace(
            "withdrawAmount > balence", "withdrawAmount > balance"))
        assert undef2 == set()

    def test_flags_standalone_typo(self):
        assert "balence" in static_undefined_names(STANDALONE_SCRIPT)

    def test_empty_on_syntax_error(self):
        assert static_undefined_names("def broken(:") == set()

    def test_does_not_flag_function_params(self):
        code = ("from z3 import *\n"
                "def helper(a, b):\n"
                "    return a + b\n"
                "x = helper(1, 2)\n"
                "print(x)\n")
        assert static_undefined_names(code) == set()


class TestPreflightFix:
    def test_preflight_fixes_harness_bare_name(self):
        fixed = preflight_fix(HARNESS_SCRIPT)
        assert fixed is not None
        assert "V['totalSupply']" in fixed
        assert static_undefined_names(fixed) == set()

    def test_preflight_fixes_standalone_typo(self):
        fixed = preflight_fix(STANDALONE_SCRIPT)
        assert fixed is not None
        assert "withdrawAmount > balance" in fixed

    def test_preflight_noop_on_clean_script(self):
        assert preflight_fix(CLEAN_SCRIPT) is None

    def test_preflight_noop_on_empty(self):
        assert preflight_fix("") is None
        assert preflight_fix(None) is None


# ---------------------------------------------------------------------------
# 6. Persistence
# ---------------------------------------------------------------------------

class TestPersistence:
    def test_persist_writes_expected_shape(self, tmp_path):
        attempts = [{"phase": "run", "status": "error", "error": "boom"}]
        final = {"status": "sat", "repairs_used": 1}
        path = persist_repair_log(tmp_path, "withdraw(uint256)", attempts, final)
        assert path is not None
        with open(path, encoding="utf-8") as f:
            payload = json.load(f)
        assert payload["focus_function"] == "withdraw(uint256)"
        assert payload["final_status"] == "sat"
        assert payload["repairs_used"] == 1
        assert payload["attempts"] == attempts
        # function-name chars sanitized out of the filename
        assert "(" not in path and ")" not in path

    def test_persist_creates_missing_dir(self, tmp_path):
        nested = tmp_path / "does" / "not" / "exist"
        path = persist_repair_log(nested, "f", [], {"status": "unsat"})
        assert path is not None and nested.exists()

    def test_persist_failure_is_nonfatal(self, tmp_path):
        # A file where a directory is needed -> OSError -> None, no raise.
        blocker = tmp_path / "blocker"
        blocker.write_text("x")
        assert persist_repair_log(blocker, "f", [], {"status": "sat"}) is None


# ---------------------------------------------------------------------------
# 7. CEGIS integration — the designed-behaviour fix
# ---------------------------------------------------------------------------

class _SpyAgent:
    """Fake LLM: counts calls; fails the test if the deterministic layer
    should have skipped it."""
    def __init__(self, reply=None):
        self.calls = 0
        self.reply = reply or "```python\nprint('Property holds')\n```"

    def invoke(self, messages):
        self.calls += 1
        import types
        return types.SimpleNamespace(content=self.reply)


class _ScriptedRunZ3:
    """Returns pre-scripted results, recording every code it was handed."""
    def __init__(self, results):
        self.results = list(results)
        self.codes = []

    def __call__(self, code):
        self.codes.append(code)
        return self.results.pop(0)


def _make_cegis(run_results, reply=None):
    from domain.cegis import CEGIS
    agent = _SpyAgent(reply)
    tool = _ScriptedRunZ3(run_results)
    return CEGIS(agent=agent, run_z3_tool=tool), agent, tool


class TestCEGISDeterministicLayer:
    def test_preflight_fixes_before_first_run_llm_never_called(self, monkeypatch):
        cegis, agent, tool = _make_cegis([{"status": "unsat", "output": "Property holds", "error": None}])
        result = cegis.run_with_repair(HARNESS_SCRIPT, max_repairs=2)
        assert result["status"] == "unsat"
        assert agent.calls == 0, "preflight must avoid any LLM call"
        assert result["repairs_used"] == 0
        # first executed code was already patched
        assert "V['totalSupply']" in tool.codes[0]
        assert len(tool.codes) == 1

    def test_runtime_nameerror_fixed_without_llm(self, monkeypatch):
        monkeypatch.setattr(z3_repair, "preflight_fix",
                            lambda code, known_symbols=None: None)
        err = ("Traceback...\nNameError: name 'totalSuply' is not defined")
        cegis, agent, tool = _make_cegis([
            {"status": "error", "output": None, "error": err},
            {"status": "sat", "output": "BUG FOUND: x=1", "error": None},
        ])
        result = cegis.run_with_repair(HARNESS_SCRIPT, max_repairs=2)
        assert result["status"] == "sat"
        assert result["repairs_used"] == 0, "no LLM repair should be consumed"
        assert result["deterministic_repairs"] == 1
        assert agent.calls == 0
        assert result["counterexample"]["assignments"] == {"x": 1}

    def test_semantic_error_falls_back_to_llm(self, monkeypatch):
        monkeypatch.setattr(z3_repair, "preflight_fix",
                            lambda code, known_symbols=None: None)
        cegis, agent, tool = _make_cegis([
            {"status": "error", "output": None, "error": "z3.z3types.Z3Exception: b'maxim...'"},
            {"status": "unsat", "output": "Property holds", "error": None},
        ])
        result = cegis.run_with_repair(HARNESS_SCRIPT, max_repairs=2)
        assert result["status"] == "unsat"
        assert result["repairs_used"] == 1
        assert result["deterministic_repairs"] == 0
        assert agent.calls == 1

    def test_llm_budget_still_bounded(self, monkeypatch):
        monkeypatch.setattr(z3_repair, "preflight_fix",
                            lambda code, known_symbols=None: None)
        cegis, agent, tool = _make_cegis([
            {"status": "error", "output": None, "error": "boom 1"},
            {"status": "error", "output": None, "error": "boom 2"},
            {"status": "error", "output": None, "error": "boom 3"},
        ])
        result = cegis.run_with_repair(HARNESS_SCRIPT, max_repairs=1)
        assert result["status"] == "error"
        assert result["repairs_used"] == 1
        assert agent.calls == 1
        assert len(tool.codes) == 2  # initial run + one repair re-run

    def test_repair_log_persisted(self, tmp_path, monkeypatch):
        from domain import config
        monkeypatch.setattr(config, "DEBUG_FOLDER", tmp_path)
        cegis, agent, tool = _make_cegis([{"status": "unsat", "output": "Property holds", "error": None}])
        cegis.run_with_repair(CLEAN_SCRIPT, max_repairs=2,
                              focus_function="deposit(uint256)")
        logs = list(tmp_path.glob("z3_repair_deposit*"))
        assert len(logs) == 1
        payload = json.loads(logs[0].read_text(encoding="utf-8"))
        assert payload["focus_function"] == "deposit(uint256)"
        assert payload["final_status"] == "unsat"
        assert any(a["phase"] == "run" for a in payload["attempts"])

    def test_executor_passes_harness_symbols_and_focus(self):
        """executor_node must feed the harness registry + focus function
        into run_with_repair so deterministic repair has full context."""
        from domain.graph_nodes import executor_node

        seen = {}

        class _RecordingCEGIS:
            def run_with_repair(self, z3_code, max_repairs=None, **kwargs):
                seen.update(kwargs)
                return {"status": "unsat", "output": "Property holds",
                        "repairs_used": 0, "deterministic_repairs": 0}

        state = {
            "z3_code": "from z3 import *",
            "iterations": 0, "executor_runs": 0,
            "current_focus_function": "withdraw(uint256)",
            # empty code: symbols still flow to CEGIS, but the vacuity probe
            # short-circuits (no real subprocess in the test)
            "semantic_harness": {"code": "",
                                 "symbols": {"totalSupply": "z3sym_0",
                                             "shares": "z3sym_1"}},
            "findings": [{"id": 1}],
        }
        executor_node(state, _RecordingCEGIS())
        assert seen["known_symbols"] == ["shares", "totalSupply"]
        assert seen["focus_function"] == "withdraw(uint256)"

    def test_executor_survives_missing_harness(self):
        from domain.graph_nodes import executor_node

        class _RecordingCEGIS:
            def run_with_repair(self, z3_code, max_repairs=None, **kwargs):
                assert kwargs["known_symbols"] == []
                return {"status": "unsat", "output": "Property holds",
                        "repairs_used": 0, "deterministic_repairs": 0}

        state = {"z3_code": "from z3 import *", "iterations": 0,
                 "executor_runs": 0, "findings": [{"id": 1}]}
        out = executor_node(state, _RecordingCEGIS())
        assert out["z3_result"]["status"] == "unsat"
