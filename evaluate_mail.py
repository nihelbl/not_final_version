"""
Évaluation mail uniquement — avec enrichissement domain
"""
import json
import requests
import time
from collections import defaultdict

API_BASE = "http://127.0.0.1:8000"
DATASET  = "mail_dataset.json"
TIMEOUT  = 600
DELAY    = 3.0

THREAT_LEVEL_TO_LABEL = {
    "critical": "malicious",
    "high":     "malicious",
    "medium":   "malicious",
    "low":      "clean",
    "clean":    "clean",
    "unknown":  "clean",
}

def map_label(threat_level: str) -> str:
    return THREAT_LEVEL_TO_LABEL.get((threat_level or "").lower().strip(), "clean")

def evaluate():
    with open(DATASET, encoding="utf-8") as f:
        data = json.load(f)

    # Filtre mail uniquement
    dataset = [d for d in data if d.get("type") in ("mail", "email") and d.get("value", "").strip()]
    print(f"\n{'='*60}")
    print(f"  Évaluation MAIL — {len(dataset)} indicateurs")
    print(f"{'='*60}\n")

    results = []
    y_true  = []
    y_pred  = []
    stats   = {"total": 0, "success": 0, "errors": 0,
                "rag_used": 0, "domain_enriched": 0, "fallback": 0}

    for i, entry in enumerate(dataset, 1):
        indicator = entry["value"].strip()
        true_label = entry["label"].strip().lower()
        stats["total"] += 1

        print(f"[{i:03d}/{len(dataset)}] {indicator[:55]:<55} | expected={true_label} ", end="", flush=True)

        try:
            resp = requests.post(
                f"{API_BASE}/ioc/analyze",
                json={"indicator": indicator},
                params={"force_rag": "true"},
                timeout=TIMEOUT
            )
            resp.raise_for_status()
            response = resp.json()
        except Exception as e:
            print(f"→ ERREUR : {e}")
            stats["errors"] += 1
            results.append({"indicator": indicator, "true_label": true_label,
                             "status": "error", "error": str(e)})
            time.sleep(DELAY)
            continue

        llm          = response.get("llm_analysis", {})
        threat_level = llm.get("threat_level", "unknown")
        predicted    = map_label(threat_level)
        rag_used     = llm.get("rag_used", False)
        fallback     = llm.get("fallback", False)
        domain_sig   = llm.get("domain_signals")
        correct      = predicted == true_label

        y_true.append(true_label)
        y_pred.append(predicted)
        stats["success"]  += 1
        stats["rag_used"] += int(rag_used)
        stats["fallback"] += int(fallback)
        if domain_sig:
            stats["domain_enriched"] += 1

        status = "✅" if correct else "❌"
        domain_info = f" domain_vt={domain_sig.get('vt_malicious',0)}" if domain_sig else ""
        print(f"→ pred={predicted:9} ({threat_level:8}){domain_info} rag={'oui' if rag_used else 'non'} {status}")

        results.append({
            "indicator":       indicator,
            "true_label":      true_label,
            "threat_level":    threat_level,
            "predicted_label": predicted,
            "correct":         correct,
            "rag_used":        rag_used,
            "fallback":        fallback,
            "domain_signals":  domain_sig,
            "status":          "success",
        })

        time.sleep(DELAY)

    # ── Métriques ──────────────────────────────────────────
    if not y_true:
        print("Aucun résultat."); return

    total   = len(y_true)
    correct = sum(t == p for t, p in zip(y_true, y_pred))
    accuracy = correct / total

    classes = ["malicious", "clean"]
    print(f"\n{'='*60}")
    print(f"  RÉSULTATS MAIL (avec enrichissement domain)")
    print(f"{'='*60}")
    print(f"  Total        : {total}")
    print(f"  Accuracy     : {accuracy*100:.2f}%")
    print(f"  RAG activé   : {stats['rag_used']}/{total}")
    print(f"  Domain enrich: {stats['domain_enriched']}/{total}")
    print(f"  Fallback     : {stats['fallback']}/{total}")
    print(f"  Erreurs      : {stats['errors']}")

    print(f"\n  PAR CLASSE :")
    for cls in classes:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == cls and p == cls)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != cls and p == cls)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == cls and p != cls)
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        rec  = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
        print(f"  [{cls:9}] P={prec:.3f} R={rec:.3f} F1={f1:.3f} (TP={tp} FP={fp} FN={fn})")

    # Confusion matrix
    print(f"\n  Confusion Matrix :")
    print(f"  {'':15} {'pred_malicious':>15} {'pred_clean':>12}")
    for cls in classes:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == cls and p == cls)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == cls and p != cls)
        print(f"  {cls:15} {tp:>15} {fn:>12}")

    print(f"\n{'='*60}\n")

    # Sauvegarde
    with open("mail_results.json", "w", encoding="utf-8") as f:
        json.dump({
            "accuracy": round(accuracy, 4),
            "stats": stats,
            "results": results
        }, f, indent=2, ensure_ascii=False)
    print("  Résultats → mail_results.json\n")

if __name__ == "__main__":
    evaluate()
