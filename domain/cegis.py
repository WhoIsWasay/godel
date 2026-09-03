"""domain/cegis.py — Phase 2: real counterexample-guided repair loop.

Previously an empty shell: the CEGIS prompt loaded but nothing used it. Now:

  run_with_repair(z3_code)
      1. Executes the script via the injected run_z3 tool.
      2. On execution ERROR, feeds the exact error + script to the LLM
         (prompts/cegis_prompt.txt) for a bounded number of repairs and re-runs.
      3. On SAT, extracts concrete counterexample assignments from the output
         so downstream nodes (gatekeeper PoC generation, bug_report) get
         attacker-controlled values instead of prose.

Bounded by `max_repairs` (default 2) — the graph's own EXECUTOR_MAX_ITERATIONS
loop still bounds total refinement cycles above this layer.
"""

import logging
import re

from langchain_core.messages import SystemMessage, HumanMessage

from domain import config, z3_repair
from domain.llm_utils import call_with_retry, content_to_text, guarded_invoke

logger = logging.getLogger(__name__)

_CEX_PAIR_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_$.]*)\s*[:=]\s*(-?\d+)")

# Zero-arg build_model() call site (the property's entry point). The harness
# definition `def build_model(witness_bound=None):` is NOT matched — its parens
# are non-empty — so injection only rewrites the call, never the definition.
_BUILD_MODEL_CALL_RE = re.compile(r"\bbuild_model\(\s*\)")


def _is_timeout(result: dict) -> bool:
    """True when a run_z3 result is a Z3 TIMEOUT (subprocess killed at
    Z3_TIMEOUT_SECONDS), as opposed to a syntax/NameError/quality-gate failure.

    A timeout means the property is undecidable-or-slow for Z3 (nonlinear
    integer arithmetic over unbounded Int symbols). NO rewrite fixes that — an
    LLM "repair" just hands back another script that times out again. Callers
    use this to stop spending money/time on a futile repair loop and to mark the
    verdict terminal-inconclusive instead of looping back to the specifier."""
    return (result.get("status") == "error"
            and "timeout" in (result.get("error") or "").lower())


def _inject_witness_bound(z3_code: str, bound: int) -> str:
    """Rewrites build_model() -> build_model(witness_bound=<bound>) so the SAME
    composed harness script re-solves with every uint256 symbol additionally
    capped to `bound`. Returns z3_code unchanged when there is no call site."""
    return _BUILD_MODEL_CALL_RE.sub(f"build_model(witness_bound={bound})", z3_code)


class CEGIS:
    with open(config.PROMPTS_DIR / "cegis_prompt.txt", "r", encoding="utf-8") as _f:
        SYSTEM_PROMPT = _f.read()

    def __init__(self, agent, run_z3_tool):
        self.agent = agent
        self.run_z3 = run_z3_tool

    # ------------------------------------------------------------- main API
    def run_with_repair(self, z3_code: str, max_repairs: int = None,
                        known_symbols=None, focus_function: str = None) -> dict:
        """Runs a Z3 property script with layered repair:

        1. Deterministic preflight (z3_repair.preflight_fix) patches
           statically-detectable undefined names BEFORE the first execution.
        2. On a runtime NameError, z3_repair.repair_name_error fixes it
           WITHOUT an LLM round-trip and does not consume the repair budget.
        3. Any other error falls back to the bounded LLM guided repair.

        Every error/repair is persisted to config.DEBUG_FOLDER so runs are
        diagnosable after the fact."""
        if max_repairs is None:
            max_repairs = max(1, config.EXECUTOR_MAX_ITERATIONS // 2)

        attempts = []

        preflight = z3_repair.preflight_fix(z3_code, known_symbols=known_symbols)
        if preflight and preflight != z3_code:
            z3_code = preflight
            attempts.append({"phase": "preflight", "kind": "deterministic"})
            print("      [CEGIS] preflight: undefined symbols fixed "
                  "deterministically (no LLM)")

        result = self.run_z3(z3_code)
        attempts.append({"phase": "run", "status": result.get("status"),
                         "error": result.get("error")})

        # A Z3 timeout on an unbounded nonlinear property never resolves by
        # rewriting it — every LLM repair re-runs a still-unbounded script that
        # times out again (this spun the seeded deposit re-confirm through ~12 min
        # of 30s timeouts + two ~2.5-min DeepSeek repairs to analysis_incomplete).
        # Bound the harness symbols and re-solve deterministically ONCE; if that
        # still times out, the property is undecidable for Z3 and we STOP — the
        # `not _is_timeout(result)` guard on the repair loop below prevents any
        # LLM spend on a timeout.
        if _is_timeout(result):
            bounded = self._retry_with_witness_bound(z3_code, attempts)
            if bounded is not None:
                z3_code = bounded.get("z3_code") or z3_code
                result = bounded

        repairs = 0          # LLM repairs (bounded by max_repairs)
        deterministic = 0    # LLM-free NameError fixes (bounded too)
        while result.get("status") == "error" and not _is_timeout(result) \
                and repairs < max_repairs:
            error = result.get("error") or ""
            fixed = None
            kind = None
            if deterministic < max_repairs:
                fixed = z3_repair.repair_name_error(z3_code, error, known_symbols)
                if fixed:
                    kind = "deterministic"
                    deterministic += 1
            if not fixed:
                print(f"      [CEGIS] Z3 error — guided repair attempt "
                      f"{repairs + 1}/{max_repairs}")
                fixed = self._repair_script(z3_code, error)
                if not fixed:
                    logger.warning("[CEGIS] repair LLM returned no usable code")
                    attempts.append({"phase": "repair", "kind": "llm",
                                     "error": "LLM returned no usable code"})
                    break
                kind = "llm"
                repairs += 1
            else:
                print(f"      [CEGIS] Z3 error — deterministic NameError fix "
                      f"applied (no LLM call)")
            z3_code = fixed
            result = self.run_z3(z3_code)
            attempts.append({"phase": "repair", "kind": kind,
                             "status": result.get("status"),
                             "error": result.get("error")})
            # An LLM repair can hand back a still-unbounded nonlinear property
            # that times out again. Bound + re-solve deterministically once; if it
            # is STILL a timeout the loop condition (`not _is_timeout`) exits on the
            # next check, so no further LLM budget is spent.
            if _is_timeout(result):
                bounded = self._retry_with_witness_bound(z3_code, attempts)
                if bounded is not None:
                    z3_code = bounded.get("z3_code") or z3_code
                    result = bounded

        result["repairs_used"] = repairs
        result["deterministic_repairs"] = deterministic
        if result.get("status") == "sat":
            cex = self.extract_counterexample(result.get("output") or "")
            minimized = self._minimize_witness(z3_code, cex, attempts)
            if minimized is not None:
                minimized["repairs_used"] = repairs
                minimized["deterministic_repairs"] = deterministic
                result = minimized
                cex = self.extract_counterexample(result.get("output") or "")
            result["counterexample"] = cex
        else:
            result["counterexample"] = None

        # Terminal marker for the graph router, stamped on the FINAL result: the
        # property is undecidable for Z3 within the timeout (nonlinear Int
        # arithmetic). This is INCONCLUSIVE — not a safety proof and not a
        # confirmed bug — so route_after_executor ends the graph instead of
        # re-queueing a futile specifier regeneration.
        result["z3_timeout"] = _is_timeout(result)

        if attempts:
            z3_repair.persist_repair_log(config.DEBUG_FOLDER, focus_function,
                                         attempts, result)
        return result

    # ------------------------------------------------------------ internals
    def _retry_with_witness_bound(self, z3_code: str, attempts: list) -> dict | None:
        """Deterministically rescue a Z3 TIMEOUT on an unbounded nonlinear
        property by re-solving the SAME harness-composed script with every uint256
        symbol additionally capped to [0, B].

        Why: Z3 cannot decide nonlinear integer arithmetic (mul/div of two
        symbols, e.g. `shares = (assets*totalSupply)/totalAssets`) in general, so
        an unbounded property can hit Z3_TIMEOUT_SECONDS with no verdict. Bounding
        the domain makes it finite and decidable, so it terminates. Without this
        the repair loop just re-runs a still-unbounded script that times out again
        — exactly what spun the seeded MiniVault deposit re-confirm to
        analysis_incomplete after ~6 minutes of 30s timeouts.

        Soundness: each rung only ADDS `sym <= B` to the identical property, so a
        bounded SAT is a valid witness (the concrete Forge PoC remains the final
        ground-truth check). A bounded UNSAT is NOT a safety proof — the violation
        may need magnitude above B — so only SAT is ever returned and UNSAT
        loosens the bound. A bounded TIMEOUT breaks the loop: the bounds ascend,
        so a larger domain is strictly harder and would also time out — continuing
        just burns 3 more Z3_TIMEOUT_SECONDS solves. Failing a SAT, return None to
        fall through (the caller's `not _is_timeout` guard then ends the run rather
        than spending an LLM repair). No LLM call."""
        if "build_model(" not in z3_code:
            return None  # standalone / LLM-improvised script: no bound hook
        for bound in config.WITNESS_TIMEOUT_BOUNDS:
            bounded_code = _inject_witness_bound(z3_code, bound)
            if bounded_code == z3_code:
                return None  # no zero-arg call site to inject into
            attempt = self.run_z3(bounded_code)
            status = attempt.get("status")
            attempts.append({"phase": "timeout_bound", "witness_bound": bound,
                             "status": status, "error": attempt.get("error")})
            if status == "sat":
                attempt["timeout_bounded"] = True
                attempt["witness_bound"] = bound
                print(f"      [CEGIS] Z3 timeout resolved with witness_bound <= {bound} "
                      f"— bounded nonlinear problem is decidable; SAT witness found "
                      f"(no LLM repair)")
                return attempt
            if _is_timeout(attempt):
                # Smallest undecidable bound => every larger bound is harder too.
                print(f"      [CEGIS] witness_bound <= {bound} still timed out — "
                      f"larger bounds are strictly harder; stopping bounded rescue "
                      f"(no further 30s solves, no LLM repair)")
                break
        print("      [CEGIS] witness-bounded re-solves found no SAT — ending "
              "without an LLM repair (a timeout is not rewrite-fixable)")
        return None

    def _minimize_witness(self, z3_code: str, cex: dict, attempts: list) -> dict | None:
        """Shrinks a huge SAT witness to a Forge-groundable size, soundly.

        Why: Z3 models uint256 as a bounded Int [0, 2**256-1] and does NOT
        minimize, so a SAT model can land near 2**254 (e.g. arg_assets=2.15e76).
        The Forge PoC hardcodes those as uint256 constants and its own
        `assets * totalSupply` overflows -> setUp reverts -> harness_error -> a
        REAL bug demoted to informational (the MiniVault deposit finding).

        Soundness: each rung only ADDS `sym <= B` to the SAME property. A SAT
        under a tighter bound is therefore a valid witness of the identical
        property — every original constraint still holds — just smaller and
        groundable. If every rung is UNSAT/vacuous/error, the bug genuinely needs
        large magnitude (overflow class) and we return None to KEEP the original
        full-range witness. The Phase-1 verdict is never changed; this is a pure
        Z3 re-solve with no LLM call."""
        if "build_model(" not in z3_code:
            return None  # standalone / LLM-improvised script: no bound hook
        assignments = (cex or {}).get("assignments") or {}
        if not assignments:
            return None
        if max(abs(v) for v in assignments.values()) <= config.WITNESS_GROUNDABLE_MAX:
            return None  # already groundable — skip the extra re-solves

        for bound in config.WITNESS_MINIMIZE_BOUNDS:
            bounded_code = _inject_witness_bound(z3_code, bound)
            if bounded_code == z3_code:
                return None  # no zero-arg call site to inject into
            attempt = self.run_z3(bounded_code)
            status = attempt.get("status")
            attempts.append({"phase": "minimize", "witness_bound": bound,
                             "status": status})
            if status == "sat":
                attempt["witness_minimized"] = True
                attempt["witness_bound"] = bound
                print(f"      [CEGIS] witness minimized to <= {bound} "
                      f"(groundable in Forge PoC; verdict unchanged)")
                return attempt
        print("      [CEGIS] no smaller witness — keeping full-range model "
              "(bug likely needs large magnitude)")
        return None

    def _repair_script(self, z3_code: str, error: str) -> str | None:
        """Asks the LLM to fix the failing Z3 script. Returns corrected code or None."""
        from langchain_core.messages import SystemMessage, HumanMessage

        user = f"""=== FAILING Z3 CODE ===
{z3_code}

=== EXECUTION ERROR ===
{error[:4000]}

Return ONLY the corrected full Python code block."""
        try:
            response = call_with_retry(lambda: guarded_invoke(self.agent, [
                SystemMessage(content=self.SYSTEM_PROMPT),
                HumanMessage(content=user),
            ]))
        except Exception as e:
            logger.error("[CEGIS] repair invoke failed: %s", e)
            return None

        raw = content_to_text(response.content).strip()
        raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
        if "```python" in raw:
            return raw.split("```python")[1].split("```")[0].strip()
        if "```" in raw:
            parts = raw.split("```")
            return parts[-2].strip() if len(parts) >= 3 else raw.strip()
        if "from z3 import" in raw or "build_model" in raw:
            return raw
        return None

    @staticmethod
    def extract_counterexample(sat_output: str) -> dict:
        """Parses 'BUG FOUND:' payloads into structured assignments.

        Understands both raw solver.model() dumps and key=value lines; falls
        back to a truncated raw string when nothing structured is found."""
        body = sat_output.split("BUG FOUND:", 1)[1] if "BUG FOUND:" in sat_output else sat_output
        pairs = {k: int(v) for k, v in _CEX_PAIR_RE.findall(body)}
        cex = {"assignments": pairs}
        if not pairs:
            cex["raw"] = body.strip()[:400]
        else:
            cex["raw"] = " ".join(body.split())[:400]
        return cex
