"""
domain/rag.py
─────────────
RAG retrieval bridge for Gödel.

This module connects the PropertyGenerator (specifier node) to the
findings_v2 vector database. It:

  1. Builds one or more search queries from an Isolator finding
     (intent, constraint, target_function, relevant_code).
  2. Calls Infrastructure.postgres.retrieve() (vector search + cross-encoder
     rerank) with full terminal logging of every score.
  3. Computes a Precision@K proxy:
        relevant  = vuln_class match OR word-overlap(Jaccard) with the finding
        P@K       = #relevant in top-K / K
     (No human labels exist for live findings, so this is a diagnostic proxy,
      exactly like eval_ab.py's auto-judge.)
  4. Returns findings in the shape PropertyGenerator.format_findings() expects
     (title_normalized / vuln_class / severity / description / code_snippet),
     plus diagnostics the pipeline can log.

RAG is intentionally non-fatal: if the DB or Ollama is down, the caller gets
an empty list (pipeline continues without historical context) plus a clear
terminal warning.
"""

import re
import time
import json
import logging

logger = logging.getLogger(__name__)

# Relevance proxy thresholds (mirror domain/inspector.py Jaccard logic).
WORD_MIN_LEN    = 4        # only "significant" words participate in overlap
INTENT_JACCARD  = 0.30     # min Jaccard between finding intent and retrieved text
TITLE_JACCARD   = 0.25     # min Jaccard between finding intent and retrieved title


def _raglog(msg: str):
    line = f"[RAG] {msg}"
    print(line, flush=True)
    logger.info(line)


def _words(text: str) -> set:
    if not text:
        return set()
    return set(w.lower() for w in re.findall(r"\b\w{%d,}\b" % WORD_MIN_LEN, text))


def _jaccard(a: str, b: str) -> float:
    wa, wb = _words(a), _words(b)
    if not wa or not wb:
        return 0.0
    return len(wa & wb) / len(wa | wb)


# ---------------------------------------------------------------------------
# 1. Query building — turn a single Isolator finding into search queries
# ---------------------------------------------------------------------------
def build_queries(finding: dict, max_queries: int = 3) -> list[str]:
    queries = []
    intent = (finding.get("intent") or "").strip()
    constraint = (finding.get("constraint") or "").strip()
    target_fn = (finding.get("target_function") or "").strip()
    code = (finding.get("relevant_code") or "").strip()

    if intent:
        queries.append(intent)
    if target_fn and constraint:
        queries.append(f"{target_fn} {constraint}")
    elif constraint:
        queries.append(constraint)
    if code:
        # short code excerpt carries the most concrete signal
        queries.append(code[:800])

    # dedupe while preserving order
    seen, out = set(), []
    for q in queries:
        key = q.lower()
        if key not in seen:
            seen.add(key)
            out.append(q)
    _raglog(f"build_queries() -> {len(out)} query/ies")
    for i, q in enumerate(out, 1):
        _raglog(f"    Q{i}: {q[:150]}")
    return out[:max_queries]


# ---------------------------------------------------------------------------
# 2. Relevance proxy (no human labels in the live path)
#
# The Isolator does NOT emit a `vuln_class` (it emits `class: "isolated"`), so
# we infer the finding's likely vulnerability class from its intent text via
# keyword scoring (same approach as eval_ab.py's auto-judge), then declare a
# retrieved row relevant if its stored vuln_class matches the inferred class
# OR the Jaccard word-overlap with the intent crosses the threshold.
# ---------------------------------------------------------------------------
CLASS_KEYWORDS = {
    "reentrancy":          ["reentrancy", "reentrant", "external call", "CEI", "checks-effects",
                            "callback", "state update before transfer", "drain", "recursive"],
    "arithmetic":          ["overflow", "underflow", "rounding", "rounds down", "rounds up",
                            "integer division", "precision", "division before", "floor",
                            "zero shares", "share price", "exchange rate"],
    "access_control":      ["access control", "onlyowner", "modifier", "unauthorized",
                            "anyone can", "any caller", "privilege", "missing owner check",
                            "admin function", "permission"],
    "oracle_manipulation": ["oracle", "flash loan", "spot price", "manipulation", "stale",
                            "twap", "slot0", "price feed", "undercollateralized"],
    "state_management":    ["stale state", "sync", "not updated", "before the", "debt",
                            "accounting", "retroactive", "cached"],
    "denial_of_service":   ["denial of service", "dos", "unbounded loop", "gas limit",
                            "out of gas", "exhaust", "block gas", "array"],
    "token_accounting":    ["erc20", "transfer", "transferfrom", "return value", "balance",
                            "shares", "mint", "burn", "approval", "donation"],
    "front_running":       ["front", "sandwich", "mev", "slippage", "deadline", "priority",
                            "transaction order", "mempool"],
    "input_validation":    ["zero address", "no check", "not validated", "missing check",
                            "input", "parameter", "boundary", "sanit"],
    "logic_error":         ["logic", "operator", "comparison", "off-by-one", "wrong",
                            "incorrect", "never", "always", "condition"],
    "proxy_storage":       ["proxy", "storage collision", "delegatecall", "eip-1967",
                            "implementation slot", "upgrade", "slot", "initialize"],
}


def infer_vuln_class(intent: str) -> str:
    """Best-effort vulnerability-class guess for a finding intent (keyword votes)."""
    if not intent:
        return ""
    text = intent.lower()
    best_class, best_score = "", 0
    for cls, kws in CLASS_KEYWORDS.items():
        score = sum(1 for kw in kws if kw in text)
        if score > best_score:
            best_class, best_score = cls, score
    return best_class if best_score >= 2 else ""


def is_relevant(row: dict, finding: dict) -> tuple[bool, str]:
    """Returns (relevant, reason). Relevant if the retrieved row's stored
    vuln_class matches the finding's inferred class OR Jaccard overlap with
    the intent crosses the threshold."""
    intent = finding.get("intent") or ""
    title = row.get("title_normalized") or ""
    embed_text = row.get("embed_text") or row.get("description") or ""
    row_class = (row.get("vuln_class") or "").strip().lower()

    # 1. Explicit class (if the caller provided one)
    if finding.get("vuln_class"):
        if finding["vuln_class"].strip().lower() == row_class:
            return True, f"vuln_class match ({row_class})"

    # 2. Inferred class (keyword votes on the intent)
    inferred = infer_vuln_class(intent)
    if inferred and inferred == row_class:
        return True, f"inferred class match ({inferred})"

    # 3. Jaccard word-overlap fallback
    if intent:
        t_j = _jaccard(intent, title)
        e_j = _jaccard(intent, embed_text)
        if e_j >= INTENT_JACCARD or t_j >= TITLE_JACCARD:
            return True, f"jaccard (title={t_j:.2f}, text={e_j:.2f})"
    return False, "no match"


def compute_precision_at_k(retrieved: list[dict], finding: dict, k: int = 5) -> dict:
    """P@K with per-item relevance reasons."""
    top = retrieved[:k]
    flags = []
    reasons = []
    for r in top:
        rel, reason = is_relevant(r, finding)
        flags.append(rel)
        reasons.append(reason)

    pk = (sum(flags) / k) if k > 0 else 0.0
    return {
        "k": k,
        "n": len(top),
        "relevant": flags,
        "reasons": reasons,
        "p_at_k": round(pk, 4),
    }


# ---------------------------------------------------------------------------
# 3. Main entry — retrieve historical findings for the specifier
# ---------------------------------------------------------------------------
def retrieve_findings_for_specifier(finding: dict,
                                    final_top_k: int = 5,
                                    top_k_per_query: int = 10) -> tuple[list[dict], dict]:
    """
    Full RAG round-trip for one Isolator finding.
    Returns (formatted_findings, diagnostics).
    formatted_findings is ready for PropertyGenerator.format_findings().
    Diagnostics contains scores + P@K for terminal logging and future
    aggregation (precision logger).
    """
    t0 = time.time()
    _raglog("=" * 72)
    _raglog(f"SPECIFIER RAG RETRIEVAL for function: {finding.get('target_function')}")

    queries = build_queries(finding, max_queries=3)
    if not queries:
        _raglog("No queries derivable from finding — returning empty context.")
        return [], {"error": "no_queries", "elapsed": time.time() - t0}

    try:
        from Infrastructure.postgres import retrieve
        results = retrieve(queries,
                           top_k_per_query=top_k_per_query,
                           final_top_k=final_top_k)
    except ImportError as e:
        # Missing dependency (e.g. psycopg2/httpx/sentence-transformers not
        # installed). This silently disables RAG for the whole run, so make it
        # impossible to miss. (C4 fix)
        _raglog("=" * 72)
        _raglog("!!! RAG DISABLED — MISSING DEPENDENCY !!!")
        _raglog(f"    {type(e).__name__}: {e}")
        _raglog("    Install full requirements to enable historical retrieval:")
        _raglog("        pip install -r requirements.txt")
        _raglog("    Continuing WITHOUT historical context (quality degraded).")
        _raglog("=" * 72)
        return [], {"error": f"rag_disabled_missing_dependency: {e}", "elapsed": time.time() - t0}
    except Exception as e:
        _raglog(f"RETRIEVAL FAILED (non-fatal): {type(e).__name__}: {e}")
        return [], {"error": str(e), "elapsed": time.time() - t0}

    # Precision@K proxy diagnostics
    precisions = {k: compute_precision_at_k(results, finding, k)
                  for k in (1, 3, final_top_k)}
    inferred = infer_vuln_class(finding.get("intent") or "")
    _raglog("----- PRECISION@K (relevance proxy) -----")
    _raglog(f"  inferred vuln_class: {inferred or '(none)'}")
    for k, p in precisions.items():
        _raglog(f"  P@{p['k']}: {p['p_at_k']}  ({sum(p['relevant'])}/{p['n']} relevant)  "
                f"reasons={p['reasons']}")

    # Format for PropertyGenerator.format_findings()
    formatted = []
    for r in results:
        formatted.append({
            "title_normalized": r.get("title_normalized") or "",
            "vuln_class": r.get("vuln_class") or "",
            "severity": r.get("severity") or "",
            "description": r.get("description") or "",
            "code_snippet": r.get("code_snippet") or "",
            "rerank_score": r.get("rerank_score"),
            "cosine_score": r.get("score"),
        })

    diagnostics = {
        "queries": queries,
        "precisions": precisions,
        "n_retrieved": len(results),
        "elapsed": round(time.time() - t0, 2),
    }
    _raglog(f"SPECIFIER RAG DONE — {len(results)} findings in {diagnostics['elapsed']}s")
    return formatted, diagnostics


# ---------------------------------------------------------------------------
# 4. Standalone benchmark runner (used by the RAG-only test harness)
# ---------------------------------------------------------------------------
def run_rag_benchmark(findings: list[dict],
                      final_top_k: int = 5,
                      top_k_per_query: int = 10) -> dict:
    """
    Runs retrieval over a batch of findings, aggregates P@K, and returns a
    summary dict for logging/reporting. Used by the RAG-only test harness.
    """
    _raglog("=" * 72)
    _raglog(f"RAG BENCHMARK: {len(findings)} queries  "
            f"(top_k_per_query={top_k_per_query}, final_top_k={final_top_k})")

    all_precisions = {k: [] for k in (1, 3, final_top_k)}
    per_query = []
    total_elapsed = 0.0

    for i, finding in enumerate(findings, 1):
        _raglog(f"\n--- Query {i}/{len(findings)}: "
                f"{(finding.get('intent') or finding.get('query') or '')[:80]} ---")
        _, diag = retrieve_findings_for_specifier(finding,
                                                  final_top_k=final_top_k,
                                                  top_k_per_query=top_k_per_query)
        total_elapsed += diag.get("elapsed", 0)
        for k in all_precisions:
            p = diag.get("precisions", {}).get(k)
            if p:
                all_precisions[k].append(p["p_at_k"])
        per_query.append({
            "label": finding.get("label") or finding.get("target_function") or i,
            "elapsed": diag.get("elapsed", 0),
            "precisions": {k: diag.get("precisions", {}).get(k, {}).get("p_at_k")
                           for k in (1, 3, final_top_k)},
        })

    summary = {"per_query": per_query, "elapsed_total": round(total_elapsed, 2)}
    _raglog("\n" + "=" * 72)
    _raglog("RAG BENCHMARK SUMMARY")
    for k in (1, 3, final_top_k):
        vals = all_precisions[k]
        mean = round(sum(vals) / len(vals), 4) if vals else 0.0
        summary[f"mean_p@{k}"] = mean
        _raglog(f"  MEAN P@{k}: {mean}  (n={len(vals)})")
    _raglog(f"  Total elapsed: {total_elapsed:.1f}s")
    _raglog("=" * 72)
    return summary
