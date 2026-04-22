import argparse
import json
import time
import requests
import os
from datetime import datetime
from collections import defaultdict

try:
    from report import print_ioc_report
    HAS_REPORT = True
except ImportError:
    HAS_REPORT = False

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────

DELAY_BETWEEN_REQUESTS = 1.5
REQUEST_TIMEOUT        = 600

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
# APPEL API
# ──────────────────────────────────────────────

def call_api_force_rag(indicator: str, ioc_type: str, api_url: str) -> dict:
    try:
        resp = requests.post(
            f"{api_url}/ioc/analyze",
            json={"indicator": indicator},
            params={"force_rag": "true"},
            timeout=REQUEST_TIMEOUT,
            headers={
                "Content-Type":               "application/json",
                "ngrok-skip-browser-warning": "true"
            }
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": str(e)}


# ──────────────────────────────────────────────
# MAPPING VERDICT
# ──────────────────────────────────────────────

def map_threat_level(threat_level: str, ioc_type: str = "") -> str:
    tl = (threat_level or "").lower().strip()
    if ioc_type in ("hash", "mail", "email"):
        return "malicious" if tl in ("critical", "high") else "clean"
    return "malicious" if tl in ("critical", "high", "medium") else "clean"


def extract_prediction(api_response: dict):
    llm          = api_response.get("llm_analysis", {})
    threat_level = llm.get("threat_level", "unknown")
    rag_used     = llm.get("rag_used", False)
    fallback     = llm.get("fallback", False)
    rag_skipped  = llm.get("rag_skipped", False)
    predicted    = map_threat_level(threat_level)
    return threat_level, predicted, rag_used, fallback, rag_skipped


# ──────────────────────────────────────────────
# MÉTRIQUES
# ──────────────────────────────────────────────

def compute_metrics(y_true: list, y_pred: list) -> dict:
    classes = ["malicious", "clean"]
    total   = len(y_true)
    correct = sum(1 for t, p in zip(y_true, y_pred) if t == p)
    accuracy = correct / total if total > 0 else 0.0

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

    macro_p  = sum(per_class[c]["precision"] for c in classes) / len(classes)
    macro_r  = sum(per_class[c]["recall"]    for c in classes) / len(classes)
    macro_f1 = sum(per_class[c]["f1"]        for c in classes) / len(classes)

    return {
        "accuracy":        round(accuracy, 4),
        "macro_precision": round(macro_p, 4),
        "macro_recall":    round(macro_r, 4),
        "macro_f1":        round(macro_f1, 4),
        "per_class":       per_class,
        "total":           total,
        "correct":         correct,
    }


def compute_metrics_by_type(results: list) -> dict:
    by_type = defaultdict(lambda: {"y_true": [], "y_pred": []})
    for r in results:
        if r.get("status") == "success":
            t = r["ioc_type"]
            by_type[t]["y_true"].append(r["true_label"])
            by_type[t]["y_pred"].append(r["predicted_label"])
    return {
        ioc_type: compute_metrics(data["y_true"], data["y_pred"])
        for ioc_type, data in by_type.items()
    }


# ──────────────────────────────────────────────
# SAUVEGARDE PAR IOC (fichier texte)
# ──────────────────────────────────────────────

def save_ioc_result_txt(
    txt_path: str,
    idx: int,
    indicator: str,
    ioc_type: str,
    true_label: str,
    predicted_label: str,
    threat_level: str,
    rag_used: bool,
    fallback: bool,
    rag_skipped: bool,
    api_response: dict,
):
    """Ajoute une ligne détaillée par IOC dans le fichier texte de résultats."""
    llm     = api_response.get("llm_analysis", {})
    correct = predicted_label == true_label
    status  = "CORRECT" if correct else "WRONG"
    summary = (llm.get("summary") or "").replace("\n", " ").strip()
    score   = llm.get("score", "N/A")

    with open(txt_path, "a", encoding="utf-8") as f:
        f.write(f"[{idx:04d}] {status}\n")
        f.write(f"  indicator    : {indicator}\n")
        f.write(f"  type         : {ioc_type}\n")
        f.write(f"  true_label   : {true_label}\n")
        f.write(f"  predicted    : {predicted_label}\n")
        f.write(f"  threat_level : {threat_level}\n")
        f.write(f"  score        : {score}\n")
        f.write(f"  rag_used     : {rag_used}\n")
        f.write(f"  rag_skipped  : {rag_skipped}\n")
        f.write(f"  fallback     : {fallback}\n")
        f.write(f"  summary      : {summary[:120]}\n")
        f.write("\n")


def save_summary_txt(
    txt_path: str,
    metrics: dict,
    metrics_by_type: dict,
    stats: dict,
    dataset_path: str,
    y_true: list,
    y_pred: list,
):
    """Ajoute le bloc de métriques globales à la fin du fichier texte."""
    sep = "=" * 60

    # Confusion matrix
    matrix    = [[0, 0], [0, 0]]
    label_idx = {"malicious": 0, "clean": 1}
    for t, p in zip(y_true, y_pred):
        i = label_idx.get(t, 1)
        j = label_idx.get(p, 1)
        matrix[i][j] += 1
    tp = matrix[0][0]; fp = matrix[1][0]
    fn = matrix[0][1]; tn = matrix[1][1]

    with open(txt_path, "a", encoding="utf-8") as f:
        f.write(f"\n{sep}\n")
        f.write(f"  RAPPORT D'ÉVALUATION — RAG + Gemma\n")
        f.write(f"{sep}\n")
        f.write(f"  Dataset      : {dataset_path}\n")
        f.write(f"  Date         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Total IOC    : {stats['total']}\n")
        f.write(f"  Succès       : {stats['success']}  |  Erreurs : {stats['errors']}\n")
        f.write(f"  RAG activé   : {stats['rag_used']}  |  RAG skippé : {stats['rag_skipped']}\n")
        f.write(f"  Fallback     : {stats['fallback']}\n")
        f.write(f"{sep}\n\n")

        f.write(f"  MÉTRIQUES GLOBALES\n")
        f.write(f"  {'Accuracy'  :20} : {metrics['accuracy']:.4f}  ({metrics['accuracy']*100:.2f}%)\n")
        f.write(f"  {'Precision' :20} : {metrics['macro_precision']:.4f}\n")
        f.write(f"  {'Recall'    :20} : {metrics['macro_recall']:.4f}\n")
        f.write(f"  {'F1-Score'  :20} : {metrics['macro_f1']:.4f}\n")
        f.write(f"  {'Correct'   :20} : {metrics['correct']}/{metrics['total']}\n\n")

        f.write(f"  CONFUSION MATRIX\n")
        f.write(f"  {'':15} {'pred_malicious':>15} {'pred_clean':>12}\n")
        f.write(f"  {'real_malicious':15} {tp:>15} {fn:>12}\n")
        f.write(f"  {'real_clean':15} {fp:>15} {tn:>12}\n")
        f.write(f"  TP={tp}  FP={fp}  FN={fn}  TN={tn}\n\n")

        f.write(f"  PAR CLASSE\n")
        for cls, m in metrics["per_class"].items():
            f.write(
                f"  [{cls:9}]  P={m['precision']:.4f}  R={m['recall']:.4f}  "
                f"F1={m['f1']:.4f}  support={m['support']}\n"
            )

        f.write(f"\n  PAR TYPE D'IOC\n")
        for ioc_type, m in metrics_by_type.items():
            f.write(
                f"  [{ioc_type:8}]  Acc={m['accuracy']:.4f} ({m['accuracy']*100:.2f}%)  "
                f"F1={m['macro_f1']:.4f}  "
                f"correct={m['correct']}/{m['total']}\n"
            )

        f.write(f"\n{sep}\n\n")


# ──────────────────────────────────────────────
# AFFICHAGE CONSOLE
# ──────────────────────────────────────────────

def print_confusion_matrix(y_true: list, y_pred: list):
    matrix    = [[0, 0], [0, 0]]
    label_idx = {"malicious": 0, "clean": 1}
    for t, p in zip(y_true, y_pred):
        i = label_idx.get(t, 1)
        j = label_idx.get(p, 1)
        matrix[i][j] += 1
    print("\n  Confusion Matrix")
    print(f"  {'':15} {'malicious':>12} {'clean':>10}")
    for i, cls in enumerate(["malicious", "clean"]):
        print(f"  {cls:15} {matrix[i][0]:>12} {matrix[i][1]:>10}")
    tp = matrix[0][0]; fp = matrix[1][0]; fn = matrix[0][1]; tn = matrix[1][1]
    print(f"\n  TP={tp}  FP={fp}  FN={fn}  TN={tn}")


def print_report(metrics: dict, metrics_by_type: dict, stats: dict):
    sep = "=" * 60
    print(f"\n{sep}")
    print("  RAPPORT D'ÉVALUATION — RAG + Gemma")
    print(sep)
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
    print(f"  Correct     : {metrics['correct']}/{metrics['total']}")
    print(f"\n  PAR CLASSE")
    for cls, m in metrics["per_class"].items():
        print(f"  [{cls}]  P={m['precision']:.4f}  R={m['recall']:.4f}  F1={m['f1']:.4f}  (support={m['support']})")
    print(f"\n  PAR TYPE D'IOC")
    for ioc_type, m in metrics_by_type.items():
        print(f"  [{ioc_type:8}]  Acc={m['accuracy']:.4f} ({m['accuracy']*100:.2f}%)  F1={m['macro_f1']:.4f}")
    print(f"\n{sep}\n")


# ──────────────────────────────────────────────
# BOUCLE PRINCIPALE
# ──────────────────────────────────────────────

def evaluate(dataset_path: str, api_url: str, output_path: str, txt_path: str):
    with open(dataset_path, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    print(f"[INFO] {len(dataset)} IOC chargés depuis {dataset_path}")
    print(f"[INFO] API cible  : {api_url}")
    print(f"[INFO] Résultats  : {txt_path}")
    print(f"[INFO] Démarrage de l'évaluation...\n")

    # Initialise le fichier texte avec un header
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(f"ÉVALUATION RAG + Gemma — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Dataset : {dataset_path}\n")
        f.write(f"API     : {api_url}\n")
        f.write("=" * 60 + "\n\n")

    results = []
    y_true  = []
    y_pred  = []
    stats   = {
        "total": 0, "success": 0, "errors": 0,
        "rag_used": 0, "rag_skipped": 0, "fallback": 0
    }

    for i, item in enumerate(dataset):
        indicator  = item.get("value", "").strip()
        ioc_type   = item.get("type", "unknown").strip()
        true_label = item.get("label", "unknown").strip().lower()

        if not indicator:
            print(f"[WARN] IOC #{i} vide, ignoré.")
            continue

        stats["total"] += 1
        print(
            f"[{i+1:03d}/{len(dataset)}] {ioc_type:8} | "
            f"{indicator[:40]:40} | label={true_label} ",
            end="", flush=True
        )

        api_response = call_api_force_rag(indicator, ioc_type, api_url)

        if "error" in api_response and not api_response.get("llm_analysis"):
            print(f"→ ERREUR : {api_response['error']}")
            stats["errors"] += 1
            results.append({
                "indicator": indicator, "ioc_type": ioc_type,
                "true_label": true_label, "status": "error",
                "error": api_response.get("error")
            })
            # Sauvegarde l'erreur dans le fichier texte aussi
            with open(txt_path, "a", encoding="utf-8") as f:
                f.write(f"[{i+1:04d}] ERROR\n")
                f.write(f"  indicator : {indicator}\n")
                f.write(f"  type      : {ioc_type}\n")
                f.write(f"  error     : {api_response.get('error')}\n\n")
            time.sleep(DELAY_BETWEEN_REQUESTS)
            continue

        # Extraction du verdict
        threat_level, predicted_label, rag_used, fallback, rag_skipped = extract_prediction(api_response)

        y_true.append(true_label)
        y_pred.append(predicted_label)

        correct = "✓" if predicted_label == true_label else "✗"
        print(
            f"→ pred={predicted_label:9} ({threat_level:8}) {correct}  "
            f"rag={'oui' if rag_used else 'non'}"
        )

        stats["success"]     += 1
        stats["rag_used"]    += int(rag_used)
        stats["rag_skipped"] += int(rag_skipped)
        stats["fallback"]    += int(fallback)

        result_entry = {
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
        }
        results.append(result_entry)

        # ── Sauvegarde immédiate dans le fichier texte ──
        save_ioc_result_txt(
            txt_path       = txt_path,
            idx            = i + 1,
            indicator      = indicator,
            ioc_type       = ioc_type,
            true_label     = true_label,
            predicted_label= predicted_label,
            threat_level   = threat_level,
            rag_used       = rag_used,
            fallback       = fallback,
            rag_skipped    = rag_skipped,
            api_response   = api_response,
        )

        # Affichage rapport détaillé (optionnel)
        if HAS_REPORT:
            print_ioc_report(api_response, show_evidence=False)

        time.sleep(DELAY_BETWEEN_REQUESTS)

    # ── Métriques finales ──
    if not y_true:
        print("[ERREUR] Aucun résultat valide.")
        return

    metrics         = compute_metrics(y_true, y_pred)
    metrics_by_type = compute_metrics_by_type(results)

    # Console
    print_confusion_matrix(y_true, y_pred)
    print_report(metrics, metrics_by_type, stats)

    # ── Sauvegarde résumé dans le fichier texte ──
    save_summary_txt(
        txt_path        = txt_path,
        metrics         = metrics,
        metrics_by_type = metrics_by_type,
        stats           = stats,
        dataset_path    = dataset_path,
        y_true          = y_true,
        y_pred          = y_pred,
    )

    print(f"[INFO] Résultats texte → {txt_path}")

    # ── Sauvegarde JSON complète ──
    output = {
        "meta": {
            "date":              datetime.now().isoformat(),
            "dataset":           dataset_path,
            "api_url":           api_url,
            "total_ioc":         stats["total"],
            "force_rag_mode":    True,
            "threshold_mapping": THREAT_LEVEL_TO_LABEL,
        },
        "stats":           stats,
        "metrics":         metrics,
        "metrics_by_type": metrics_by_type,
        "results":         results,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"[INFO] Résultats JSON  → {output_path}")


# ──────────────────────────────────────────────
# POINT D'ENTRÉE
# ──────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Évaluation RAG + Gemma — PFE Cybersécurité")
    parser.add_argument("--dataset", required=True,  help="Chemin vers le dataset JSON")
    parser.add_argument("--url",     required=True,  help="URL de base de l'API")
    parser.add_argument("--output",  default="resultats_eval.json", help="Fichier JSON de sortie")
    parser.add_argument("--txt",     default="resultats_eval.txt",  help="Fichier texte de sortie")
    args = parser.parse_args()

    evaluate(
        dataset_path = args.dataset,
        api_url      = args.url.rstrip("/"),
        output_path  = args.output,
        txt_path     = args.txt,
    )