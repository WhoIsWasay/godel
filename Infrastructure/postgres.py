import httpx
import psycopg2
import psycopg2.extras
from sentence_transformers import CrossEncoder
import os
from dotenv import load_dotenv
load_dotenv()


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

cross_encoder = CrossEncoder("cross-encoder/ms-marco-MiniLM-L-6-v2")


def embed(text: str) -> list[float]:
    response = httpx.post(OLLAMA_URL, json={
        "model": EMBED_MODEL,
        "input": text,
    }, timeout=60)
    return response.json()["embeddings"][0][:2000]  # truncate to match index


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
        return [dict(row) for row in cur.fetchall()]


def retrieve(queries: list[str], top_k_per_query: int = 10, final_top_k: int = 5) -> list[dict]:
    conn = psycopg2.connect(**DB_CONFIG)

    # 1. Embed + vector search each query
    candidates = {}
    for query in queries:
        embedding = embed(query)
        results = vector_search(conn, embedding, top_k=top_k_per_query)
        for row in results:
            uid = row["id"]
            if uid not in candidates:
                candidates[uid] = row  # dedup on uid, first occurrence wins

    conn.close()

    # 2. Cross-encoder rerank
    candidate_list = list(candidates.values())
    
    # Use the original query joined as context for reranking
    combined_query = " ".join(queries)
    pairs = [(combined_query, row["embed_text"] or row["description"] or "") for row in candidate_list]
    
    scores = cross_encoder.predict(pairs)

    for i, row in enumerate(candidate_list):
        row["rerank_score"] = float(scores[i])

    reranked = sorted(candidate_list, key=lambda x: x["rerank_score"], reverse=True)

    return reranked[:final_top_k]