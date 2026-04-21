import pathlib

EMBEDDING_MODEL = "all-MiniLM-L6-v2"
CHROMA_DB_PATH  = ".chroma_db"
COLLECTION_NAME = "tip_rag"
DATA_DIR        = pathlib.Path("rag_data")
TOP_K           = 5
MIN_SCORE       = 0.0
JSONL_SOURCES   = [
    "detections.jsonl",
    "intel_notes.jsonl",
    "playbooks.jsonl",
]