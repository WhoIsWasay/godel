import json
from datetime import datetime

from domain.extractor import OutputExtractor


# ==========================================
# COUNTEREXAMPLE NORMALIZATION (Phase 6 #29)
# Z3 can emit unrealistic "timestamp" values (huge SMT model ints). Clamp
# time-hinted variables into a realistic unix-seconds window for display.
# Raw values remain untouched in z3_result (PoC generation uses the raw ones).
# ==========================================
UNIX_WINDOW = (946684800, 4102444800)  # 2000-01-01 .. 2100-01-01 UTC
TIME_HINTS = ("time", "timestamp", "deadline", "expiry", "expiration", "period", "duration")


def normalize_value(name, value):
    if not isinstance(value, int):
        return value
    lowered = name.lower()
    if any(hint in lowered for hint in TIME_HINTS):
        lo, hi = UNIX_WINDOW
        return min(max(value, lo), hi)
    return value


def normalize_counterexample(cex: dict) -> dict:
    if not cex:
        return cex
    return {name: normalize_value(name, value) for name, value in cex.items()}


def build_finding(finding, state, fixed_code, test_suite, forge_output, qc_status) -> dict:
    raw_intent = finding.get("intent") or "Logic Flaw Detected"
    title = " ".join(raw_intent.split()[:8]).replace('"', "").replace("'", "") + "..."

    z3_result = state.get("z3_result") or {}
    z3_output = z3_result.get("output") if z3_result.get("status") == "sat" else None
    counterexample = OutputExtractor.parse_z3_counterexample(z3_output) if z3_output else {}
    counterexample = normalize_counterexample(counterexample)

    rag_diag = state.get("rag_diagnostics") or {}
    rag_precisions = rag_diag.get("precisions") or {}
    rag_metrics = {
        "queries": rag_diag.get("queries", []),
        "n_retrieved": rag_diag.get("n_retrieved", 0),
        "elapsed": rag_diag.get("elapsed"),
        "p_at_1": (rag_precisions.get(1) or {}).get("p_at_k"),
        "p_at_3": (rag_precisions.get(3) or {}).get("p_at_k"),
        "p_at_5": (rag_precisions.get(5) or {}).get("p_at_k"),
    }

    return {
        "contract": state.get("contract_name", "unknown"),
        "function": finding.get("target_function", "unknown"),
        "severity": finding.get("severity_guess", "medium"),
        "title": title,
        "summary": raw_intent,
        "root_cause": finding.get("constraint", ""),
        "invariant": finding.get("relevant_code", ""),
        "counterexample": counterexample,
        "z3_proof_code": state.get("z3_code", ""),
        "poc_test_code": test_suite,
        "forge_output": forge_output,
        "qc_status": qc_status,
        "isolated_code": finding.get("relevant_code", ""),
        "fix_code": fixed_code,
        "rag_metrics": rag_metrics,
        "metadata": {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "iterations": state.get("iterations", 0),
            "status": qc_status,
        },
    }


def validate_finding(f: dict) -> list:
    errors = []
    required = [
        "contract", "function", "severity", "title", "summary", "root_cause",
        "invariant", "counterexample", "z3_proof_code", "poc_test_code",
        "forge_output", "qc_status", "isolated_code", "fix_code", "metadata",
    ]
    for key in required:
        if key not in f:
            errors.append(f"missing field: {key}")
    return errors
