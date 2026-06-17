"""
core/fofa_rag.py
-----------------
RAG retrieval over the fofa_archive table.

For each user prompt:
    1. Embed the prompt with sentence-transformers all-MiniLM-L6-v2
       (~80 MB, runs on CPU in ~5-30 ms per query)
    2. Cosine-similarity rank against every archive entry's embedding
    3. Return the top-K most relevant (nl, query) pairs

We persist the embedding for each archive row in the `embedding` BLOB
column so we don't re-compute on every retrieval. New rows are embedded
lazily on first use of `retrieve()`.

Public API:
    retrieve(prompt, k=5)        -> list[dict] of nearest archive entries
    ensure_embeddings()          -> int (count of newly embedded rows)
    rebuild_index()              -> int (forces re-embed of everything)
"""

from __future__ import annotations

import logging
import os
from typing import Optional

import numpy as np

from core.fofa_archive import (
    DB_PATH,
    archive_size,
    get_all_entries,
    init_archive_table,
    update_embedding,
)
from database.db import get_connection

logger = logging.getLogger(__name__)

EMBED_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
EMBED_DIM = 384   # all-MiniLM-L6-v2 output dimension


# ── Lazy model loader ────────────────────────────────────────────────────────
_model = None


def _get_model():
    global _model
    if _model is not None:
        return _model
    from sentence_transformers import SentenceTransformer
    logger.info(f"[RAG] Loading embedding model {EMBED_MODEL_NAME} (first run downloads ~80MB)...")
    _model = SentenceTransformer(EMBED_MODEL_NAME)
    logger.info("[RAG] Embedding model ready")
    return _model


# ── Embedding helpers ────────────────────────────────────────────────────────
def _encode(texts: list[str]) -> np.ndarray:
    model = _get_model()
    vecs = model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
    return np.asarray(vecs, dtype=np.float32)


def _vec_to_blob(v: np.ndarray) -> bytes:
    return np.asarray(v, dtype=np.float32).tobytes()


def _blob_to_vec(b: bytes) -> Optional[np.ndarray]:
    if not b:
        return None
    try:
        v = np.frombuffer(b, dtype=np.float32)
        if v.size != EMBED_DIM:
            return None
        return v
    except Exception:
        return None


# ── Index maintenance ────────────────────────────────────────────────────────
def ensure_embeddings(db_path: str = DB_PATH) -> int:
    """
    Embed any archive rows that don't have an embedding yet.
    Returns the count of newly embedded rows.
    """
    init_archive_table(db_path)
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT id, nl FROM fofa_archive WHERE embedding IS NULL"
        ).fetchall()

    if not rows:
        return 0

    texts = [r["nl"] for r in rows]
    vecs  = _encode(texts)

    for r, v in zip(rows, vecs):
        update_embedding(r["id"], _vec_to_blob(v), db_path)

    logger.info(f"[RAG] Embedded {len(rows)} new archive entries")
    return len(rows)


def rebuild_index(db_path: str = DB_PATH) -> int:
    """Force re-embedding of every row (e.g. after switching models)."""
    init_archive_table(db_path)
    with get_connection(db_path) as conn:
        conn.execute("UPDATE fofa_archive SET embedding = NULL")
    return ensure_embeddings(db_path)


# ── Retrieval ────────────────────────────────────────────────────────────────
def retrieve(prompt: str, k: int = 5, db_path: str = DB_PATH) -> list[dict]:
    """
    Return the top-K archive entries most similar to `prompt`.
    Each entry is a dict with: nl, query, cve_id, source, similarity.
    """
    if not prompt or not prompt.strip():
        return []

    # Make sure every row has an embedding before we score.
    ensure_embeddings(db_path)

    rows = get_all_entries(db_path, with_embedding=True)
    if not rows:
        return []

    # Build matrix of archive embeddings; skip any rows missing one.
    valid_rows = []
    matrix = []
    for r in rows:
        v = _blob_to_vec(r.get("embedding"))
        if v is None:
            continue
        valid_rows.append(r)
        matrix.append(v)

    if not valid_rows:
        return []

    M = np.vstack(matrix)                # (N, 384) — already L2-normalized
    q = _encode([prompt])[0]             # (384,)   — already L2-normalized
    scores = M @ q                       # cosine, since both are unit vectors

    # Top-K
    k = max(1, min(k, len(valid_rows)))
    top_idx = np.argpartition(-scores, range(k))[:k]
    top_idx = top_idx[np.argsort(-scores[top_idx])]

    out = []
    for i in top_idx:
        r = valid_rows[i]
        out.append({
            "nl":         r["nl"],
            "query":      r["query"],
            "cve_id":     r.get("cve_id"),
            "source":     r["source"],
            "similarity": float(scores[i]),
        })
    return out


# ── Self-test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    print(f"archive size: {archive_size()}")
    print(f"embedded    : {ensure_embeddings()}")

    for q in [
        "find FortiGate firewalls in India",
        "Roundcube webmail exposed",
        "Microsoft Exchange ProxyShell servers",
        "Cisco IOS XE 17.9",
        "find anything",
    ]:
        print(f"\nQ: {q}")
        for hit in retrieve(q, k=4):
            print(f"  {hit['similarity']:.3f}  [{hit['source']:8s}]  {hit['nl'][:60]:60s}  -> {hit['query'][:80]}")
