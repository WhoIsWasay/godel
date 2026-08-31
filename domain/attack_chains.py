"""Attack-chain pre-computer for cross-boundary compositional attacks.

Detects multi-step attack sequences where:
  1. Attacker calls an entry-point function (public/external, no access control)
  2. That function writes attacker-controllable state (allowance, balances, ...)
  3. The attacker then exploits that state via a SEPARATE action (often an
     ERC-20 transferFrom, a redeem, a liquidate — possibly NOT defined in the
     contract under audit)

This catches the class of bugs that per-function analysis misses: the exploit's
final step is performed by the ATTACKER from outside the contract, not by any
function inside it. Example: TrusterLenderPool.flashLoan calls
IERC20.approve(attacker, MAX), and the attacker drains via transferFrom —
no function in TrusterLenderPool performs the drain, so a per-function audit
cannot prove it.

Deterministic: pure function of the abstracter's facts dict. Offline-testable
against mock analyses. Output is an XML block injected into the hunter prompt
alongside the existing <compositional_context>.
"""
from __future__ import annotations

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)


# State variables whose write is attacker-controllable in the common case:
# an attacker can influence the value via function parameters, msg.sender,
# or the return value of an attacker-supplied external call.
_HIGH_RISK_PATTERNS = ("allowance", "approval", "approved")
_MEDIUM_RISK_PATTERNS = (
    "balance", "owner", "admin", "role", "authorized",
    "paused", "whitelist", "blacklist",
)
# Access-control modifiers that mark a function as non-attacker-reachable.
_ACCESS_MODIFIERS = (
    "onlyowner", "onlyadmin", "onlyrole", "onlygovernance",
    "onlykeeper", "onlymanager", "onlyoperator", "restricted",
    "onlyauthorized", "onlyallowed",
)


def _base_name(fn_key: str) -> str:
    """Strip signature: 'flashLoan(uint256,address,address,bytes)' -> 'flashLoan'."""
    return fn_key.split("(", 1)[0] if "(" in fn_key else fn_key


def _is_attacker_entry(fn_key: str, facts: dict) -> bool:
    """True if the function is callable by an attacker (no access control).

    Visibility must be public or external, and no access-control modifier
    may be present. Constructors and receive/fallback are excluded — they
    are not attacker-reachable in the sense we care about.
    """
    vis = (facts.get("visibility") or "").lower()
    if vis not in ("public", "external"):
        return False
    for m in facts.get("modifiers", []):
        if m.lower() in _ACCESS_MODIFIERS:
            return False
    base = _base_name(fn_key).lower()
    if base in ("constructor", "receive", "fallback"):
        return False
    return True


def _is_controllable_state(state_var: str) -> bool:
    """True if the state variable is plausibly attacker-controllable."""
    lower = state_var.lower()
    return any(p in lower for p in _HIGH_RISK_PATTERNS + _MEDIUM_RISK_PATTERNS)


def _chain_risk(state_var: str, attacker_reads: bool,
                writer_has_ext_calls: bool) -> str:
    """Classify a single chain's risk.

    High: attacker-controllable allowance/approval is both written and
          later read — classic approve-then-drain.
    Medium: attacker-controllable state flow without the allowance pattern,
            or the writer has external calls (parameters potentially
            attacker-supplied).
    Low: everything else.
    """
    lower = state_var.lower()
    if attacker_reads and any(p in lower for p in _HIGH_RISK_PATTERNS):
        return "high"
    if attacker_reads:
        return "medium"
    if writer_has_ext_calls:
        return "medium"
    return "low"


def detect_attack_chains(analysis: Optional[dict]) -> list:
    """Find attacker-reachable state-flow chains of length 2.

    Returns a list of dicts sorted by risk (high first):
        {
            "entry": str,              # attacker entry-point function
            "state_var": str,          # state variable written by entry
            "attacker_action": str,    # description of the follow-up action
            "risk": "high" | "medium" | "low",
            "writer_has_ext_calls": bool,
        }

    Empty list if analysis is None or no chains found.
    """
    if not analysis:
        return []

    functions = analysis.get("functions", {})
    if not functions:
        return []

    # Per-function index: writes / reads / attacker-reachability.
    writers = {}       # state_var -> [fn_key]
    readers = {}       # state_var -> [fn_key]
    entry_points = {}  # fn_key -> bool (attacker-reachable)

    for fn_key, facts in functions.items():
        entry_points[fn_key] = _is_attacker_entry(fn_key, facts)
        for var in facts.get("state_writes", []):
            writers.setdefault(var, []).append(fn_key)
        for var in facts.get("state_reads", []):
            readers.setdefault(var, []).append(fn_key)

    chains = []
    seen = set()

    for state_var, writer_fns in writers.items():
        if not _is_controllable_state(state_var):
            continue

        reader_fns = readers.get(state_var, [])
        attacker_read_targets = [r for r in reader_fns if entry_points.get(r, False)]

        for writer in writer_fns:
            if not entry_points.get(writer, False):
                continue

            writer_facts = functions.get(writer, {})
            writer_ext = bool(writer_facts.get("external_calls")
                              or writer_facts.get("has_external_call"))

            if attacker_read_targets:
                # Length-2 chain: entry -> write -> attacker reads via another entry.
                for reader in attacker_read_targets:
                    if reader == writer:
                        continue
                    pair_key = (writer, state_var, reader)
                    if pair_key in seen:
                        continue
                    seen.add(pair_key)
                    risk = _chain_risk(state_var, True, writer_ext)
                    chains.append({
                        "entry": _base_name(writer),
                        "state_var": state_var,
                        "attacker_action": (
                            f"Attacker calls {_base_name(reader)} to exploit "
                            f"the {state_var} set by {_base_name(writer)}"
                        ),
                        "risk": risk,
                        "writer_has_ext_calls": writer_ext,
                    })
            else:
                # No in-contract attacker reader — still flag a dangling write
                # (the exploit may use a standard token interface like
                # transferFrom that isn't in the analyzed contract).
                chain_key = (writer, state_var)
                if chain_key in seen:
                    continue
                seen.add(chain_key)
                risk = _chain_risk(state_var, False, writer_ext)
                chains.append({
                    "entry": _base_name(writer),
                    "state_var": state_var,
                    "attacker_action": (
                        f"Attacker exploits {state_var} via a separate call "
                        f"(e.g., transferFrom, redeem, liquidate)"
                    ),
                    "risk": risk,
                    "writer_has_ext_calls": writer_ext,
                })

    risk_order = {"high": 0, "medium": 1, "low": 2}
    chains.sort(key=lambda c: (risk_order.get(c["risk"], 3),
                               c["entry"], c["state_var"]))
    return chains[:5]


def render_attack_chain_context(analysis: Optional[dict],
                                focus_function: str) -> str:
    """Render an <attack_chain_context> XML block for the hunter.

    Only chains involving `focus_function` are included. Empty string when
    no chain is relevant — the caller should skip injection in that case.
    """
    if not analysis:
        return ""

    chains = detect_attack_chains(analysis)
    if not chains:
        return ""

    focus_base = _base_name(focus_function)
    relevant = [
        c for c in chains
        if c["entry"] == focus_base or focus_base in c["attacker_action"]
    ]
    if not relevant:
        return ""

    lines = ["<attack_chain_context>"]
    lines.append("  WARNING: This function may be the entry to a multi-step "
                 "cross-boundary attack.")
    lines.append("  The attacker's final exploit step may happen OUTSIDE this "
                 "contract (e.g., an ERC-20 transferFrom after this function "
                 "sets allowance).")

    for c in relevant:
        lines.append(f'  <chain risk="{c["risk"]}">')
        lines.append(f"    <attacker_entry>{c['entry']}</attacker_entry>")
        lines.append(f"    <state_written>{c['state_var']}</state_written>")
        lines.append(f"    <attacker_followup>{c['attacker_action']}</attacker_followup>")
        if c["writer_has_ext_calls"]:
            lines.append("    <signal>writer has external calls — parameters may "
                         "be attacker-supplied</signal>")
        lines.append("  </chain>")

    lines.append("  Consider: what can the attacker do AFTER this function "
                 "returns, given the state it wrote?")
    lines.append("  If this function sets an allowance, balance, or other "
                 "attacker-controllable value, trace the EXPLOITATION path, "
                 "not just the write.")
    lines.append("</attack_chain_context>")
    return "\n".join(lines)
