# rag/rag_retriever.py
"""Retrieval Chroma : préférer des requêtes factuelles construites côté API (voir services.rag_gate)."""
from rag.rag_indexer import get_collection, _model

def _ioc_type_for_metadata_filter(ioc_type: str | None) -> str | None:
    """Aligne le type d'IOC de l'API avec les valeurs `type` des JSONL indexés."""
    if not ioc_type:
        return None
    if ioc_type == "mail":
        return "email"
    return ioc_type


def retrieve(
    query: str,
    k: int = 5,
    min_score: float = 0.4,
    ioc_type: str = None,
    source: str = None
) -> list[dict]:
    col    = get_collection()
    q_vec  = _model.encode([query]).tolist()

    meta_ioc = _ioc_type_for_metadata_filter(ioc_type)
    where = None
    if meta_ioc and source:
        where = {"$and": [{"ioc_type": meta_ioc}, {"source": source}]}
    elif meta_ioc:
        where = {"ioc_type": meta_ioc}
    elif source:
        where = {"source": source}

    results = col.query(
        query_embeddings=q_vec,
        n_results=k,
        where=where,
        include=["documents", "metadatas", "distances"]
    )

    out = []
    for doc, meta, dist in zip(
        results["documents"][0],
        results["metadatas"][0],
        results["distances"][0]
    ):
        score = round(1 - dist, 3)

        if score >= min_score:
            out.append({
                "text":   doc,
                "source": meta["source"],
                "type":   meta["type"],
                "score":  round(score, 3)
            })
    out.sort(key=lambda x: x["score"], reverse=True)
    print(f"[RAG] '{query[:40]}' → {len(out)} résultats")
    for r in out:
        print(f"      [{r['source']}] score={r['score']} — {r['text'][:60]}")

    return out