import json
from pathlib import Path
from routers.ioc_router import detect_type

_KW_PATH = Path(__file__).parent.parent / "cybersec_keywords.json"
with open(_KW_PATH, encoding="utf-8") as f:
    _RAW = json.load(f)

# ✅ Aplatit toutes les catégories en une seule liste
_ALL_KEYWORDS: list[str] = []
for category_words in _RAW.get("cybersecurity_keywords", {}).values():
    _ALL_KEYWORDS.extend(category_words)


def classify_message(message: str) -> str:
    stripped  = message.strip()

    # Priority 1 — IOC reconnu
    if detect_type(stripped) != "unknown":
        return "ioc"

    msg_lower = stripped.lower()

    # Priority 2 — keyword cybersec (depuis le JSON aplati)
    for kw in _ALL_KEYWORDS:
        if kw.lower() in msg_lower:
            return "question"

    # Priority 3 — mots-clés français courants non couverts par le JSON
    FRENCH_FALLBACK = [
        "qu'est", "c'est quoi", "comment", "pourquoi", "explique",
        "définition", "différence", "comment fonctionne", "kesako",
        "cest quoi", "kézako", "c koi",
    ]
    for kw in FRENCH_FALLBACK:
        if kw in msg_lower:
            # Vérifie qu'il y a un mot cybersec dans le contexte
            CYBER_NOUNS = [
                "ransomware", "malware", "virus", "hack", "phish",
                "attaque", "vulnérabilité", "chiffrement", "firewall",
                "botnet", "exploit", "patch", "sécurité", "menace",
                "injection", "ddos", "zero day", "backdoor", "trojan",
            ]
            if any(n in msg_lower for n in CYBER_NOUNS):
                return "question"

    return "off_topic"