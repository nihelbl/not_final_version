import argparse
import json
import time
import requests
from datetime import datetime
from collections import defaultdict
from report import print_ioc_report

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────

# Délai entre chaque requête (évite le rate-limiting ngrok)
DELAY_BETWEEN_REQUESTS = 1.5  # secondes

# Timeout par requête vers l'API
REQUEST_TIMEOUT = 600  # secondes

# Mapping threat_level → label binaire
# Ajuste "medium" selon tes résultats : met-le dans "malicious" si ton modèle est agressif
THREAT_LEVEL_TO_LABEL = {
    "critical": "malicious",
    "high":     "malicious",
    "medium":   "malicious",
    "spam":     "malicious",
    "low":      "clean",
    "clean":    "clean",
    "unknown":  "clean",      
}


# ──────────────────────────────────────────────
# APPEL API AVEC FORCE_RAG
# ──────────────────────────────────────────────

def call_api_force_rag(indicator: str, ioc_type: str, api_url: str) -> dict:
    """
    Appelle l'endpoint /analyze en forçant le passage par RAG.
    On contourne rag_gate en appelant directement /enrich avec rag_force=true,
    ou en passant par /analyze?force_rag=true si tu l'as implémenté.

    Si ton API ne supporte pas force_rag, on appelle /analyze normalement
    et on note si RAG a été utilisé ou non dans les résultats.
    """
    payload = {"indicator": indicator}

    try:
        # Tentative 1 : avec paramètre force_rag (si implémenté dans ton router)
        resp = requests.post(
            f"{api_url}/ioc/analyze",
            json=payload,
            params={"force_rag": "true"},
            timeout=REQUEST_TIMEOUT,
            headers={
                "Content-Type": "application/json",
                "ngrok-skip-browser-warning": "true"
            }
        )
        resp.raise_for_status()
        return resp.json()

    except Exception as e:
        return {"error": str(e)}


# ──────────────────────────────────────────────
# MAPPING VERDICT → LABEL BINAIRE
# ──────────────────────────────────────────────

def map_threat_level(threat_level: str, ioc_type: str = "") -> str:
    tl = (threat_level or "").lower().strip()
    
    # Hash et email : medium = clean (signaux ambigus)
    if ioc_type in ("hash", "mail", "email"):
        return "malicious" if tl in ("critical", "high") else "clean"
    
    # IP, domain, URL : medium = malicious (signaux plus fiables)
    return "malicious" if tl in ("critical", "high", "medium") else "clean"


def extract_prediction(api_response: dict) -> tuple[str, str, bool, bool]:
    """
    Extrait depuis la réponse API :
      - threat_level brut
      - label prédit (malicious/clean)
      - rag_used : True si RAG a été activé
      - fallback : True si le LLM a utilisé le fallback à base de règles
    """
    llm = api_response.get("llm_analysis", {})
    threat_level = llm.get("threat_level", "unknown")
    rag_used     = llm.get("rag_used", False)
    fallback     = llm.get("fallback", False)
    rag_skipped  = llm.get("rag_skipped", False)

    predicted_label = map_threat_level(threat_level)
    return threat_level, predicted_label, rag_used, fallback, rag_skipped


# ──────────────────────────────────────────────
# CALCUL DES MÉTRIQUES
# ──────────────────────────────────────────────

def compute_metrics(y_true: list[str], y_pred: list[str]) -> dict:
    """
    Calcule Accuracy, Precision, Recall, F1 pour chaque classe + macro.
    Classes : malicious / clean
    """
    classes = ["malicious", "clean"]
    metrics = {}

    total = len(y_true)
    correct = sum(1 for t, p in zip(y_true, y_pred) if t == p)
    accuracy = correct / total if total > 0 else 0.0

    # Par classe
    per_class = {}
    for cls in classes:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == cls and p == cls)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != cls and p == cls)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == cls and p != cls)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1        = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        per_class[cls] = {
            "precision": round(precision, 4),
            "recall":    round(recall, 4),
            "f1":        round(f1, 4),
            "tp": tp, "fp": fp, "fn": fn,
            "support": sum(1 for t in y_true if t == cls)
        }

    # Macro (moyenne simple sur les classes)
    macro_precision = sum(per_class[c]["precision"] for c in classes) / len(classes)
    macro_recall    = sum(per_class[c]["recall"]    for c in classes) / len(classes)
    macro_f1        = sum(per_class[c]["f1"]        for c in classes) / len(classes)

    metrics = {
        "accuracy":        round(accuracy, 4),
        "macro_precision": round(macro_precision, 4),
        "macro_recall":    round(macro_recall, 4),
        "macro_f1":        round(macro_f1, 4),
        "per_class":       per_class,
    }
    return metrics


def compute_metrics_by_type(results: list[dict]) -> dict:
    """Calcule les métriques séparément pour chaque type d'IOC."""
    by_type = defaultdict(lambda: {"y_true": [], "y_pred": []})

    for r in results:
        if r.get("status") == "success":
            t = r["ioc_type"]
            by_type[t]["y_true"].append(r["true_label"])
            by_type[t]["y_pred"].append(r["predicted_label"])

    metrics_by_type = {}
    for ioc_type, data in by_type.items():
        metrics_by_type[ioc_type] = compute_metrics(data["y_true"], data["y_pred"])

    return metrics_by_type


# ──────────────────────────────────────────────
# CONFUSION MATRIX (affichage texte)
# ──────────────────────────────────────────────

def print_confusion_matrix(y_true: list[str], y_pred: list[str]):
    classes = ["malicious", "clean"]
    matrix = [[0, 0], [0, 0]]

    label_idx = {"malicious": 0, "clean": 1}
    for t, p in zip(y_true, y_pred):
        i = label_idx.get(t, 1)
        j = label_idx.get(p, 1)
        matrix[i][j] += 1

    print("\n  Confusion Matrix (lignes=réel, colonnes=prédit)")
    print(f"  {'':15} {'malicious':>12} {'clean':>10}")
    for i, cls in enumerate(classes):
        print(f"  {cls:15} {matrix[i][0]:>12} {matrix[i][1]:>10}")

    tn = matrix[1][1]
    fp = matrix[1][0]
    fn = matrix[0][1]
    tp = matrix[0][0]
    print(f"\n  TP={tp}  FP={fp}  FN={fn}  TN={tn}")


# ──────────────────────────────────────────────
# RAPPORT FINAL
# ──────────────────────────────────────────────

def print_report(metrics: dict, metrics_by_type: dict, stats: dict):
    sep = "=" * 60
    print(f"\n{sep}")
    print("  RAPPORT D'ÉVALUATION — RAG + Gemma")
    print(sep)
    print(f"  Date       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Total IOC  : {stats['total']}")
    print(f"  Succès     : {stats['success']}  |  Erreurs : {stats['errors']}")
    print(f"  RAG activé : {stats['rag_used']}  |  RAG skippé : {stats['rag_skipped']}")
    print(f"  Fallback   : {stats['fallback']}")
    print(sep)
    print(f"\n  MÉTRIQUES GLOBALES")
    print(f"  {'Accuracy'  :20} : {metrics['accuracy']:.4f}  ({metrics['accuracy']*100:.2f}%)")
    print(f"  {'Precision' :20} : {metrics['macro_precision']:.4f}")
    print(f"  {'Recall'    :20} : {metrics['macro_recall']:.4f}")
    print(f"  {'F1-Score'  :20} : {metrics['macro_f1']:.4f}")
    print(f"\n  PAR CLASSE")
    for cls, m in metrics["per_class"].items():
        print(f"  [{cls}]  P={m['precision']:.4f}  R={m['recall']:.4f}  F1={m['f1']:.4f}  (support={m['support']})")
    print(f"\n  PAR TYPE D'IOC")
    for ioc_type, m in metrics_by_type.items():
        print(f"  [{ioc_type:8}]  Acc={m['accuracy']:.4f}  F1={m['macro_f1']:.4f}")
    print(f"\n{sep}\n")


# ──────────────────────────────────────────────
# BOUCLE PRINCIPALE D'ÉVALUATION
# ──────────────────────────────────────────────

def evaluate(dataset_path: str, api_url: str, output_path: str):
    # Chargement du dataset
    with open(dataset_path, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    print(f"[INFO] {len(dataset)} IOC chargés depuis {dataset_path}")
    print(f"[INFO] API cible : {api_url}")
    print(f"[INFO] Démarrage de l'évaluation...\n")

    results   = []
    y_true    = []
    y_pred    = []
    stats     = {"total": 0, "success": 0, "errors": 0,
                 "rag_used": 0, "rag_skipped": 0, "fallback": 0}

    for i, item in enumerate(dataset):
        indicator  = item.get("value", "").strip()
        ioc_type   = item.get("type", "unknown").strip()
        true_label = item.get("label", "unknown").strip().lower()

        if not indicator:
            print(f"[WARN] IOC #{i} vide, ignoré.")
            continue

        stats["total"] += 1

        # Appel API
        print(f"[{i+1:03d}/{len(dataset)}] {ioc_type:8} | {indicator[:40]:40} | label={true_label} ", end="", flush=True)

        api_response = call_api_force_rag(indicator, ioc_type, api_url)
        print(f"DEBUG llm_analysis: {api_response.get('llm_analysis', {})}")

        if "error" in api_response and not api_response.get("llm_analysis"):
            print(f"→ ERREUR : {api_response['error']}")
            stats["errors"] += 1
            results.append({
                "indicator": indicator,
                "ioc_type": ioc_type,
                "true_label": true_label,
                "status": "error",
                "error": api_response.get("error")
            })
            time.sleep(DELAY_BETWEEN_REQUESTS)
            continue

        # Extraction du verdict
        threat_level, predicted_label, rag_used, fallback, rag_skipped = extract_prediction(api_response)

        y_true.append(true_label)
        y_pred.append(predicted_label)

        correct = "✓" if predicted_label == true_label else "✗"
        print(f"→ pred={predicted_label:9} ({threat_level:8}) {correct}  rag={'oui' if rag_used else 'non'}")

        stats["success"]     += 1
        stats["rag_used"]    += int(rag_used)
        stats["rag_skipped"] += int(rag_skipped)
        stats["fallback"]    += int(fallback)

        results.append({
            "indicator":       indicator,
            "ioc_type":        ioc_type,
            "true_label":      true_label,
            "threat_level":    threat_level,
            "predicted_label": predicted_label,
            "correct":         predicted_label == true_label,
            "rag_used":        rag_used,
            "rag_skipped":     rag_skipped,
            "fallback":        fallback,
            "status":          "success",
        })
        
        print_ioc_report(api_response, show_evidence=False)

        time.sleep(DELAY_BETWEEN_REQUESTS)

    # Calcul des métriques
    if not y_true:
        print("[ERREUR] Aucun résultat valide. Vérifier l'URL de l'API.")
        return

    metrics          = compute_metrics(y_true, y_pred)
    metrics_by_type  = compute_metrics_by_type(results)

    # Affichage
    print_confusion_matrix(y_true, y_pred)
    print_report(metrics, metrics_by_type, stats)

    # Sauvegarde JSON
    output = {
        "meta": {
            "date":          datetime.now().isoformat(),
            "dataset":       dataset_path,
            "api_url":       api_url,
            "total_ioc":     stats["total"],
            "force_rag_mode": True,
            "threshold_mapping": THREAT_LEVEL_TO_LABEL,
        },
        "stats":           stats,
        "metrics":         metrics,
        "metrics_by_type": metrics_by_type,
        "results":         results,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"[INFO] Résultats sauvegardés dans : {output_path}")


# ──────────────────────────────────────────────
# POINT D'ENTRÉE
# ──────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Évaluation RAG + Gemma — Cybersécurité PFE")
    parser.add_argument("--dataset", required=True,  help="Chemin vers le fichier JSON du dataset de test")
    parser.add_argument("--url",     required=True,  help="URL de base de l'API (ex: http://xxxx.ngrok.io)")
    parser.add_argument("--output",  default="resultats_eval.json", help="Fichier de sortie JSON")
    args = parser.parse_args()

    evaluate(
        dataset_path=args.dataset,
        api_url=args.url.rstrip("/"),
        output_path=args.output,
    )
