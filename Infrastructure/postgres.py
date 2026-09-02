import httpx
import psycopg2
import psycopg2.extras
import os
import sys
import time
import logging
from pathlib import Path
from dotenv import load_dotenv

# Root-anchored (never CWD-dependent, matches domain/pipeline.py)
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

logger = logging.getLogger(__name__)

# RAG logs go through the standard logger only — no print(). The two-tier
# filter in domain/config.py then suppresses them from the console on INFO
# runs (console floor is WARNING+) while the file handler at OUTPUT_DIR
# keeps every line for ParadeDB / forensic replay. Set GODEL_CONSOLE_DEBUG=1
# to restore full RAG noise on the terminal when diagnosing retrieval.
os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
os.environ.setdefault("HF_HUB_VERBOSITY", "error")
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
os.environ.setdefault("SENTENCE_TRANSFORMERS_VERBOSITY", "error")

# HuggingFace's own loggers are registered independently of the Python root;
# pin them to ERROR so their "unauthenticated requests" warning never reaches
# any handler regardless of how the caller configures logging.
for _name in ("huggingface_hub", "huggingface_hub.utils._http",
              "transformers", "sentence_transformers"):
    logging.getLogger(_name).setLevel(logging.ERROR)


def _raglog(msg: str):
    # INFO by default; the caller can pass level=logging.DEBUG to keep a
    # noisy per-call line (e.g. embed() timings) off the file log as well.
    logger.info(f"[RAG] {msg}")


OLLAMA_URL  = "http://localhost:11434/api/embed"
EMBED_MODEL = "qwen3-embedding:8b"
EMBED_DIM   = 2000


DB_CONFIG = {
    "host":     os.environ.get("DB_HOST", "localhost"),
    "port":     int(os.environ.get("DB_PORT", 5433)),
    "dbname":   os.environ.get("DB_NAME"),
    "user":     os.environ.get("DB_USER"),
    "password": os.environ.get("DB_PASSWORD"),
}


# ---------------------------------------------------------------------------
# Cross-encoder is loaded lazily (first call only) so importing this module
# stays cheap for the pipeline when RAG is not in the hot path. A lock guards
# the lazy init because the specifier node runs concurrently (ThreadPool).
# ---------------------------------------------------------------------------
import threading
_cross_encoder = None
_cross_encoder_loaded_at = None
_cross_encoder_lock = threading.Lock()


def _get_cross_encoder():
    global _cross_encoder, _cross_encoder_loaded_at
    if _cross_encoder is None:
        with _cross_encoder_lock:
            if _cross_encoder is None:  # double-checked under lock
                t0 = time.time()
                logger.info("[RAG] Loading cross-encoder reranker (ms-marco-MiniLM-L-6-v2)...")
                # tqdm + torch hub chatter write to stderr directly; silence them
                # around the import + constructor so the console stays clean
                # even when the two-tier filter floor is low.
                import contextlib
                with open(os.devnull, "w", encoding="utf-8") as _null, \
                     contextlib.redirect_stderr(_null):
                    from sentence_transformers import CrossEncoder
                    _cross_encoder = CrossEncoder("cross-encoder/ms-marco-MiniLM-L-6-v2")
                _cross_encoder_loaded_at = time.time() - t0
                logger.info(f"[RAG] Cross-encoder loaded in {_cross_encoder_loaded_at:.1f}s")
    return _cross_encoder


def embed(text: str) -> list[float]:
    t0 = time.time()
    try:
        response = httpx.post(OLLAMA_URL, json={
            "model": EMBED_MODEL,
            "input": text,
        }, timeout=180)  # 180s: first call loads the 8b model into VRAM
        response.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Ollama embed failed with HTTP {e.response.status_code}: "
                           f"{e.response.text[:300]}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Ollama embed request failed: {e}") from e

    payload = response.json()
    if not isinstance(payload, dict) or not payload.get("embeddings"):
        # Ollama returns {"error": "..."} payloads on failure — surface them
        # clearly instead of crashing on KeyError/IndexError.
        raise RuntimeError(f"Unexpected embed response from Ollama: {str(payload)[:300]}")
    vec = payload["embeddings"][0][:2000]  # truncate to match index
    if not vec:
        raise RuntimeError("Ollama returned an empty embedding vector")
    _raglog(f"embed() -> dim={len(vec)} in {time.time()-t0:.1f}s")
    return vec


def embed_batch(texts: list[str]) -> list[list[float]]:
    """Embed multiple texts in a single Ollama HTTP call.

    Ollama's /api/embed accepts a list for 'input' and returns all vectors in
    one response — eliminates per-query round-trip overhead (~2-14s each)."""
    if not texts:
        return []
    t0 = time.time()
    try:
        response = httpx.post(OLLAMA_URL, json={
            "model": EMBED_MODEL,
            "input": texts,
        }, timeout=180)
        response.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Ollama embed_batch failed with HTTP {e.response.status_code}: "
                           f"{e.response.text[:300]}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Ollama embed_batch request failed: {e}") from e

    payload = response.json()
    if not isinstance(payload, dict) or not payload.get("embeddings"):
        raise RuntimeError(f"Unexpected embed_batch response from Ollama: {str(payload)[:300]}")
    embeddings = payload["embeddings"]
    if len(embeddings) != len(texts):
        raise RuntimeError(f"Ollama returned {len(embeddings)} embeddings for {len(texts)} inputs")
    result = [vec[:EMBED_DIM] for vec in embeddings]
    _raglog(f"embed_batch({len(texts)} texts) -> dim={len(result[0])} in {time.time()-t0:.1f}s")
    return result


def vector_search(conn, embedding: list[float], top_k: int = 10) -> list[dict]:
    vec_str = "[" + ",".join(str(x) for x in embedding) + "]"
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT
                id,
                title_normalized,
                vuln_class,
                protocol_type,
                severity,
                description,
                code_snippet,
                embed_text,
                1 - (embedding <=> %s::vector) AS score
            FROM findings_v2
            WHERE fv_relevant = TRUE
            ORDER BY embedding <=> %s::vector
            LIMIT %s
        """, (vec_str, vec_str, top_k))
        rows = [dict(row) for row in cur.fetchall()]

    _raglog(f"vector_search() -> {len(rows)} rows:")
    for r in rows:
        _raglog(f"    sim={float(r['score']):.4f}  [{r.get('severity')}]  "
                f"{str(r.get('title_normalized'))[:70]}  class={r.get('vuln_class')}")
    return rows


def warmup_rag():
    """Preload cross-encoder and Ollama embed model at startup.

    Eliminates the cold-start penalty that otherwise hits the first finding's
    RAG call: ~21.8s HuggingFace download + ~14s Ollama VRAM load. Called once
    from run_pipeline() before any function graph spawns. Non-fatal: if models
    fail to load (e.g. CUDA OOM), the audit continues without RAG grounding."""
    from domain import config
    if not config.rag_enabled():
        _raglog("RAG disabled (GODEL_DISABLE_RAG) — skipping model warmup")
        return
    t0 = time.time()
    _raglog("Warming up RAG models...")
    try:
        _get_cross_encoder()
    except Exception as e:
        _raglog(f"Cross-encoder warmup failed (non-fatal): {e}")
    try:
        embed("warmup")
    except Exception as e:
        _raglog(f"Ollama embed warmup failed (non-fatal): {e}")
    _raglog(f"RAG warmup complete in {time.time()-t0:.1f}s")


def retrieve(queries: list[str], top_k_per_query: int = 10, final_top_k: int = 5) -> list[dict]:
    """Multi-query vector search + cross-encoder rerank with full terminal logging."""
    t0_total = time.time()
    _raglog(f"===== RETRIEVE START =====")
    _raglog(f"Queries ({len(queries)}):")
    for i, q in enumerate(queries, 1):
        _raglog(f"    Q{i}: {q[:150]}")

    conn = psycopg2.connect(**DB_CONFIG)
    try:
        # 1. Batch-embed all queries in one Ollama call, then vector search each
        t0 = time.time()
        embeddings = embed_batch(queries)
        _raglog(f"All {len(queries)} queries embedded in {time.time()-t0:.1f}s — vector search...")

        candidates = {}
        for qi, (query, embedding) in enumerate(zip(queries, embeddings), 1):
            results = vector_search(conn, embedding, top_k=top_k_per_query)
            new = 0
            for row in results:
                uid = row["id"]
                if uid not in candidates:
                    candidates[uid] = row  # dedup on uid, first occurrence wins
                    new += 1
            _raglog(f"Q{qi} added {new} new candidates (total unique: {len(candidates)})")
    finally:
        # No leaked connections when the embed/search loop raises.
        conn.close()

    # 2. Cross-encoder rerank
    encoder = _get_cross_encoder()
    candidate_list = list(candidates.values())
    _raglog(f"Candidates before rerank: {len(candidate_list)}")

    combined_query = " ".join(queries)
    pairs = [(combined_query, row["embed_text"] or row["description"] or "") for row in candidate_list]
    t0 = time.time()
    scores = encoder.predict(pairs)
    _raglog(f"Rerank scored {len(pairs)} pairs in {time.time()-t0:.1f}s")

    for i, row in enumerate(candidate_list):
        row["rerank_score"] = float(scores[i])

    reranked = sorted(candidate_list, key=lambda x: x["rerank_score"], reverse=True)
    final = reranked[:final_top_k]

    _raglog(f"----- FINAL TOP-{final_top_k} (reranked) -----")
    for i, r in enumerate(final, 1):
        _raglog(f"  #{i} rerank={r['rerank_score']:.4f} sim={float(r.get('score', 0)):.4f} "
                f"[{r.get('severity')}] {str(r.get('title_normalized'))[:70]} class={r.get('vuln_class')}")
    _raglog(f"RETRIEVE total time: {time.time()-t0_total:.1f}s")
    return final


# ---------------------------------------------------------------------------
# Run-log persistence: the noisy full log (output/godel-run-full.log) goes to
# the DB so the CI console can stay clean. Best-effort and non-fatal: GitHub-
# hosted runners can't reach the local ParadeDB, self-hosted ones can.
# ---------------------------------------------------------------------------
def save_run_log(contracts_folder: str, findings_count: int, status: str,
                 log_path) -> bool:
    try:
        text = Path(log_path).read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("[LOG DB] could not read %s: %s", log_path, e)
        return False
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS godel_run_logs (
                        id               BIGSERIAL PRIMARY KEY,
                        run_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
                        contracts_folder TEXT,
                        findings_count   INT,
                        status           TEXT,
                        log_text         TEXT
                    )
                """)
                cur.execute(
                    "INSERT INTO godel_run_logs "
                    "(contracts_folder, findings_count, status, log_text) "
                    "VALUES (%s, %s, %s, %s)",
                    (str(contracts_folder), int(findings_count), status, text))
            conn.commit()
        finally:
            conn.close()
        return True
    except Exception as e:
        logger.warning("[LOG DB] ParadeDB unreachable, run log kept on disk only: %s", e)
        return False
