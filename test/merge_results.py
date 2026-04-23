import re
import sys
import argparse
from datetime import datetime
from collections import defaultdict


# ──────────────────────────────────────────────
# PARSING D'UN FICHIER TXT
# ──────────────────────────────────────────────

def parse_ioc_blocks(txt_path: str) -> list[dict]:
    """Extrait les blocs IOC individuels depuis un fichier texte d'évaluation."""
    results = []

    with open(txt_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Chaque bloc commence par [XXXX] CORRECT ou [XXXX] WRONG ou [XXXX] ERROR
    blocks = re.split(r'\n(?=\[\d{4}\])', content)

    for block in blocks:
        block = block.strip()
        if not block or not re.match(r'\[\d{4}\]', block):
            continue

        def extract(field: str) -> str:
            m = re.search(rf'{field}\s*:\s*(.+)', block)
            return m.group(1).strip() if m else ""

        status_m = re.match(r'\[(\d{4})\]\s+(CORRECT|WRONG|ERROR)', block)
        if not status_m:
            continue

        status = status_m.group(2)
        if status == "ERROR":
            continue

        entry = {
            "idx":             int(status_m.group(1)),
            "status":          status,
            "correct":         status == "CORRECT",
            "indicator":       extract("indicator"),
            "ioc_type":        extract("type"),
            "true_label":      extract("true_label"),
            "predicted_label": extract("predicted"),
            "threat_level":    extract("threat_level"),
            "score":           extract("score"),
            "rag_used":        extract("rag_used").lower() == "true",
            "fallback":        extract("fallback").lower() == "true",
            "summary":         extract("summary"),
            "source_file":     txt_path,
        }
        results.append(entry)

    return results


# ──────────────────────────────────────────────
# CALCUL DES MÉTRIQUES
# ──────────────────────────────────────────────

def compute_metrics(y_true: list, y_pred: list) -> dict:
    classes  = ["malicious", "clean"]
    total    = len(y_true)
    correct  = sum(1 for t, p in zip(y_true, y_pred) if t == p)
    accuracy = correct / total if total > 0 else 0.0

    per_class = {}
    for cls in classes:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == cls and p == cls)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != cls and p == cls)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == cls and p != cls)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
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


# ──────────────────────────────────────────────
# RAPPORT DE FUSION
# ──────────────────────────────────────────────

def write_report(
    all_results: list,
    source_files: list,
    output_path: str,
):
    y_true = [r["true_label"]      for r in all_results]
    y_pred = [r["predicted_label"] for r in all_results]

    # Métriques globales
    global_metrics = compute_metrics(y_true, y_pred)

    # Métriques par type d'IOC
    by_type = defaultdict(lambda: {"y_true": [], "y_pred": []})
    for r in all_results:
        t = r["ioc_type"]
        by_type[t]["y_true"].append(r["true_label"])
        by_type[t]["y_pred"].append(r["predicted_label"])
    metrics_by_type = {
        t: compute_metrics(d["y_true"], d["y_pred"])
        for t, d in by_type.items()
    }

    # Stats
    rag_used    = sum(1 for r in all_results if r["rag_used"])
    fallback    = sum(1 for r in all_results if r["fallback"])
    errors      = 0  # les erreurs sont exclues du parsing

    # Confusion matrix
    matrix    = [[0, 0], [0, 0]]
    label_idx = {"malicious": 0, "clean": 1}
    for t, p in zip(y_true, y_pred):
        i = label_idx.get(t, 1)
        j = label_idx.get(p, 1)
        matrix[i][j] += 1
    tp = matrix[0][0]; fp = matrix[1][0]
    fn = matrix[0][1]; tn = matrix[1][1]

    sep = "=" * 60

    lines = []
    lines.append(f"RAPPORT GLOBAL — FUSION DES ÉVALUATIONS RAG + Gemma")
    lines.append(f"Généré le : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(sep)
    lines.append(f"Fichiers fusionnés ({len(source_files)}) :")
    for f in source_files:
        lines.append(f"  - {f}")
    lines.append("")
    lines.append(f"  Total IOC analysés : {len(all_results)}")
    lines.append(f"  RAG activé         : {rag_used}/{len(all_results)}")
    lines.append(f"  Fallback           : {fallback}/{len(all_results)}")
    lines.append(sep)

    lines.append("")
    lines.append("  MÉTRIQUES GLOBALES")
    lines.append(f"  {'Accuracy'  :20} : {global_metrics['accuracy']:.4f}  ({global_metrics['accuracy']*100:.2f}%)")
    lines.append(f"  {'Precision' :20} : {global_metrics['macro_precision']:.4f}")
    lines.append(f"  {'Recall'    :20} : {global_metrics['macro_recall']:.4f}")
    lines.append(f"  {'F1-Score'  :20} : {global_metrics['macro_f1']:.4f}")
    lines.append(f"  Correct            : {global_metrics['correct']}/{global_metrics['total']}")

    lines.append("")
    lines.append("  CONFUSION MATRIX")
    lines.append(f"  {'':15} {'pred_malicious':>15} {'pred_clean':>12}")
    lines.append(f"  {'real_malicious':15} {tp:>15} {fn:>12}")
    lines.append(f"  {'real_clean':15} {fp:>15} {tn:>12}")
    lines.append(f"  TP={tp}  FP={fp}  FN={fn}  TN={tn}")

    lines.append("")
    lines.append("  PAR CLASSE")
    for cls, m in global_metrics["per_class"].items():
        lines.append(
            f"  [{cls:9}]  P={m['precision']:.4f}  R={m['recall']:.4f}  "
            f"F1={m['f1']:.4f}  support={m['support']}"
        )

    lines.append("")
    lines.append("  PAR TYPE D'IOC")
    for ioc_type in sorted(metrics_by_type.keys()):
        m = metrics_by_type[ioc_type]
        lines.append(
            f"  [{ioc_type:8}]  "
            f"Acc={m['accuracy']:.4f} ({m['accuracy']*100:.2f}%)  "
            f"P={m['macro_precision']:.4f}  "
            f"R={m['macro_recall']:.4f}  "
            f"F1={m['macro_f1']:.4f}  "
            f"correct={m['correct']}/{m['total']}"
        )

    lines.append("")
    lines.append(sep)
    lines.append("")

    # Détail des erreurs de classification
    wrong = [r for r in all_results if not r["correct"]]
    if wrong:
        lines.append(f"  ERREURS DE CLASSIFICATION ({len(wrong)})")
        lines.append("-" * 60)
        for r in wrong:
            lines.append(
                f"  [{r['ioc_type']:8}] {r['indicator'][:45]:45} "
                f"true={r['true_label']:10} pred={r['predicted_label']:10} "
                f"({r['threat_level']})"
            )
        lines.append("")
        lines.append(sep)

    report_text = "\n".join(lines)

    # Affichage console
    print(report_text)

    # Sauvegarde
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_text + "\n")

    print(f"\n[INFO] Rapport global sauvegardé → {output_path}")


# ──────────────────────────────────────────────
# POINT D'ENTRÉE
# ──────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Fusionne plusieurs fichiers d'évaluation RAG et calcule les métriques globales"
    )
    parser.add_argument(
        "files", nargs="+",
        help="Fichiers .txt d'évaluation à fusionner (ex: resultats_hash.txt resultats_ip.txt)"
    )
    parser.add_argument(
        "--output", default="rapport_global.txt",
        help="Fichier de sortie du rapport fusionné (défaut: rapport_global.txt)"
    )
    args = parser.parse_args()

    all_results = []
    for txt_file in args.files:
        try:
            entries = parse_ioc_blocks(txt_file)
            print(f"[INFO] {txt_file} → {len(entries)} IOC chargés")
            all_results.extend(entries)
        except FileNotFoundError:
            print(f"[WARN] Fichier introuvable : {txt_file}")
        except Exception as e:
            print(f"[ERREUR] {txt_file} : {e}")

    if not all_results:
        print("[ERREUR] Aucun résultat valide trouvé.")
        sys.exit(1)

    print(f"\n[INFO] Total : {len(all_results)} IOC à analyser\n")
    write_report(all_results, args.files, args.output)