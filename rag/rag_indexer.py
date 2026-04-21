import json
import chromadb
from sentence_transformers import SentenceTransformer
from rag.rag_config import (
    EMBEDDING_MODEL, CHROMA_DB_PATH,
    COLLECTION_NAME, DATA_DIR, JSONL_SOURCES
)

_client = chromadb.PersistentClient(path=CHROMA_DB_PATH)
_model  = SentenceTransformer(EMBEDDING_MODEL)

def get_collection():
    return _client.get_or_create_collection(
        COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"}
    )

def _build_text(obj: dict, ioc_type: str) -> str:
    """Construit un texte sémantique propre sans bruit de clés JSON."""
    parts = []

    # Contexte court — utile pour filtrer sémantiquement
    obj_type = obj.get("type", "")
    if obj_type:
        parts.append(f"[{obj_type}]")         
    if ioc_type:
        parts.append(f"[{ioc_type}]")       

    # Le contenu sémantique pur — champs textuels uniquement
    for key in ("text", "content", "description", "summary", "note", "rule"):
        val = obj.get(key, "")
        if val and isinstance(val, str):
            parts.append(val.strip())

    return " ".join(parts)

def index_all_sources():
    try:
        _client.delete_collection(COLLECTION_NAME)
        print("[RAG] Collection réinitialisée")
    except Exception:
        pass
    col = get_collection()

    total = 0

    for source in JSONL_SOURCES:
        path = DATA_DIR / source
        if not path.exists():
            print(f"[RAG] Fichier introuvable : {path}")
            continue

        docs, ids, metas = [], [], []
        ioc_type = source.replace(".jsonl", "")

        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)

                text = _build_text(obj, ioc_type) 
                if not text.strip():
                    print(f"[RAG] Doc vide ignoré ({source} ligne {i})")
                    continue

                docs.append(text)
                ids.append(f"{source}_{i}")
                metas.append({
                    "source":   source,
                    "type":     ioc_type,
                    "ioc_type": obj.get("type", "generic"),
                })
            except json.JSONDecodeError:
                print(f"[RAG] Ligne invalide ignorée ({source} ligne {i})")
                continue

        if docs:
            embeddings = _model.encode(docs).tolist()
            col.upsert(
                documents=docs,
                embeddings=embeddings,
                ids=ids,
                metadatas=metas
            )
            total += len(docs)
            print(f"[RAG] {source} → {len(docs)} docs indexés")

    print(f"[RAG] Index OK — {col.count()} docs au total")
    return total