import requests, os, logging
from dotenv import load_dotenv

load_dotenv()
logger      = logging.getLogger(__name__)
LLM_API_URL = os.getenv("LLM_API_URL", "")


def _normalize_mail_auth_status(value: object) -> str:
    """Normalise SPF/DMARC/DKIM pour éviter les champs vides ambigus côté LLM."""
    s = (str(value) if value is not None else "").strip().lower()
    if not s or s in ("n/a", "na", "none", "null", "unknown", "absent", "missing", "false"):
        return "missing"
    if "permerror" in s or "neutral" in s or "softfail" in s or "permissive" in s:
        return "permissive"
    if "valid" in s or "pass" in s or "enforce" in s or "quarantine" in s or "reject" in s:
        return "valid"
    return "present"


# ── Elle reçoit juste raw_data qui est déjà collecté, et elle reformate ce dict pour l'envoyer au LLM ─────────────────────────
def _build_ti_data(ioc_type: str, raw_data: dict) -> dict:
    ioc_type = ioc_type.lower()
    
    if ioc_type == "ip":
        vt    = raw_data.get("virustotal", {})
        abuse = raw_data.get("abuseipdb", {})
        otx   = raw_data.get("otx", {})
        stats = vt.get("stats", {})
        return {
            "type": ioc_type,
            "country":            vt.get("country", "unknown"),
            "vt_verdict":         vt.get("verdict", "unknown"),
            "vt_malicious_count": stats.get("malicious", 0),
            "vt_total_engines":   sum(stats.values()) if stats else 0,
            "vt_malware_families": vt.get("tags", []),
            "abuseipdb_score":    abuse.get("abuse_score", 0),
            "otx_pulse_count":    otx.get("pulse_count", 0),
            "otx_verdict":        otx.get("verdict", "unknown"),
            "final_verdict":      raw_data.get("final_verdict", "unknown")
        }
    
    elif ioc_type == "cve":
        return {
         "type": ioc_type,
         "description": raw_data.get("description", ""),
         "severity"   : raw_data.get("severity", "N/A"),
         "cvss_score" : raw_data.get("cvss_score"),
         "cvss_vector": raw_data.get("cvss_vector"),
         "cwe"        : raw_data.get("cwe", []),
         "affected"   : raw_data.get("affected", []),
         "final_verdict": raw_data.get("risk", {}).get("level", "unknown")
     }
    
    elif ioc_type == "hash":
        vt  = raw_data.get("virustotal", {}) if "virustotal" in raw_data \
              else raw_data
        otx = raw_data.get("otx", {})
        return {
            "type": ioc_type,
            "file_type":          vt.get("file_type", "unknown"),
            "vt_malicious_count": vt.get("malicious", 0),
            "vt_suspicious":      vt.get("suspicious", 0),
            "vt_reputation":      vt.get("reputation", 0),
            "first_submission":   vt.get("first_submission", "unknown"),
            "otx_pulse_count":    otx.get("pulse_count", 0),
            "otx_malware_families": otx.get("malware_families", []),
            "mitre_attack":       vt.get("mitre_attack", []),
            "final_verdict":      raw_data.get("risk_level", "unknown")
        }

    elif ioc_type == "domain":
        vt     = raw_data.get("virustotal", {})
        ht     = raw_data.get("hackertarget", {})
        det    = vt.get("detection", {})
        return {
            "type": ioc_type,
            "registrar":          raw_data.get("registrar", "unknown"),
            "creation_date":      raw_data.get("creation_date", "unknown"),
            "ip_address":         raw_data.get("ip_address", "unknown"),
            "vt_malicious_count": det.get("malicious", 0),
            "vt_suspicious":      det.get("suspicious", 0),
            "vt_reputation":      vt.get("reputation_score", 0),
            "vt_risk_level":      vt.get("risk_level", "unknown"),
            "global_risk_level":  raw_data.get("global_risk_level", "unknown"),
            "final_verdict":      raw_data.get("global_risk_level", "unknown")
        }

    elif ioc_type == "url":
        vt  = raw_data.get("vendors", {}).get("virustotal", {})
        gsb = raw_data.get("vendors", {}).get("google_safe_browsing", {})
        pt  = raw_data.get("vendors", {}).get("phishtank", {})
        return {
            "type": ioc_type,
            "domain":             raw_data.get("domain", "unknown"),
            "ip":                 raw_data.get("ip", "unknown"),
            "vt_malicious_count": vt.get("malicious", 0),
            "vt_suspicious":      vt.get("suspicious", 0),
            "vt_verdict":         vt.get("verdict", "unknown"),
            "gsb_verdict":        gsb.get("verdict", "unknown"),
            "gsb_threats":        gsb.get("threats", []),
            "phishtank_verdict":  pt.get("verdict", "unknown"),
            "phishtank_verified": pt.get("verified", False),
            "final_verdict":      raw_data.get("final_verdict", "unknown"),
            "global_risk_level":  raw_data.get("global_risk_level", "unknown")
        }

    elif ioc_type == "mail":
        return {
            "type": ioc_type,
            "domain":       raw_data.get("domaine", "unknown"),
            "mx_servers":   len(raw_data.get("mx", [])),
            "provider":     raw_data.get("fournisseur", "unknown"),
            "spf":          raw_data.get("spf", "absent"),
            "dmarc":        raw_data.get("dmarc", "absent"),
            "alerts":       raw_data.get("alertes", []),
            "score":        raw_data.get("score", 0),
            "final_verdict": raw_data.get("verdict", "unknown")
        }

    # fallback générique
    return {**raw_data, "type": ioc_type}


# ── Fallback par type ────────────────────────────────────────
def _fallback(ti_data: dict, reason: str) -> dict:
    score = 0
    tags  = []
    ioc_type = ti_data.get("type", "ip")

    if ioc_type == "ip":
        vt  = ti_data.get("vt_malicious_count", 0)
        ab  = ti_data.get("abuseipdb_score", 0)
        otx = ti_data.get("otx_pulse_count", 0)
        if vt  > 30: score += 40; tags.append("malicious-vt")
        elif vt > 10: score += 20
        if ab  > 80: score += 35; tags.append("high-abuse")
        elif ab > 50: score += 15
        if otx > 5:  score += 25; tags.append("otx-high")
        elif otx > 0: score += 10

    elif ioc_type == "hash":
        vt = ti_data.get("vt_malicious_count", 0)
        if vt > 30: score += 60; tags.append("malicious-vt")
        elif vt > 10: score += 35; tags.append("suspicious-vt")
        elif vt > 0:  score += 15
        if ti_data.get("otx_pulse_count", 0) > 0:
            score += 20; tags.append("otx-pulse")

    elif ioc_type == "domain":
        vt     = ti_data.get("vt_malicious_count", 0)
        if vt   > 5:  score += 40; tags.append("malicious-vt")
        elif vt > 0:  score += 20

    elif ioc_type == "url":
        vt  = ti_data.get("vt_malicious_count", 0)
        gsb = ti_data.get("gsb_verdict", "clean")
        pt  = ti_data.get("phishtank_verdict", "clean")
        if vt  > 3:              score += 40; tags.append("malicious-vt")
        if gsb == "malicious":   score += 35; tags.append("google-sb")
        if pt  == "malicious":   score += 30; tags.append("phishtank")
    
    elif ioc_type == "cve":
     cvss = ti_data.get("cvss_score") or 0
     severity = ti_data.get("severity", "").upper()
     if severity == "CRITICAL" or cvss >= 9.0:
         score = 95; tags.append("critical-cve")
     elif severity == "HIGH" or cvss >= 7.0:
         score = 70; tags.append("high-cve")
     elif severity == "MEDIUM" or cvss >= 4.0:
         score = 45; tags.append("medium-cve")
     else:
         score = 20; tags.append("low-cve")

    elif ioc_type == "mail":
        mail_score = ti_data.get("score", 100)
        score = max(0, 100 - mail_score)
        alerts = ti_data.get("alerts", [])
        if "DMARC absent" in str(alerts): tags.append("no-dmarc")
        if "SPF absent"   in str(alerts): tags.append("no-spf")

    score = min(100, score)
    level = ("critical" if score >= 80 else "high"   if score >= 60 else
             "medium"   if score >= 40 else "low"    if score >= 20 else "clean")

    sources_map = {
            "ip":     ["VirusTotal", "AbuseIPDB", "OTX"],
            "hash":   ["VirusTotal", "OTX"],
            "domain": ["VirusTotal", "hackertarget"],
            "url":    ["VirusTotal", "GoogleSafeBrowsing", "PhishTank"],
            "mail":   ["MXToolbox"],
            "cve":    ["CIRCL", "NVD"]
    }

    if score <= 10:   # seuil bas
        if ioc_type == "mail":
            domain = ti_data.get("domain", "inconnu")
            mx_score = ti_data.get("score", 100)
            summary = (f"Adresse email sur {domain}. Configuration email valide (score MXToolbox {mx_score}). "
                       f"Aucune alerte. Indicateur bénin (LLM indisponible : {reason}).")
        elif ioc_type == "ip":
            ip = ti_data.get("indicator", "inconnue")
            summary = f"IP {ip} : aucune détection malveillante, faible score de réputation. Propre (fallback : {reason})."
        elif ioc_type == "domain":
            domain = ti_data.get("indicator", "inconnu")
            summary = f"Domaine {domain} : aucun signal malveillant. Classification propre (fallback : {reason})."
        else:
            summary = f"Aucune menace détectée. Indicateur propre (fallback : {reason})."
    else:
        # Conserver l'ancien comportement pour les indicateurs suspects/malveillants
        summary = f"Analyse par regles (LLM offline : {reason})."
    
    level = ("critical" if score >= 80 else "high"   if score >= 60 else
             "medium"   if score >= 40 else "low"    if score >= 20 else "clean")
    
    return {
        "threat_level": level,
        "score": score,
        "summary": summary,
        "tags": tags,
        "sources_ti": sources_map.get(ioc_type, ["VirusTotal"]),
        "fallback": True
    }


# ── envoie les données TI au LLM ──────────────────────────────────────
def enrich_ioc(ioc_type: str, raw_data: dict) -> dict:
    """
    Point d'entrée principal.
    ioc_type : 'ip' | 'hash' | 'domain' | 'url' | 'mail' | 'cve'
    raw_data : réponse brute du service correspondant
    """
    ti_data = _build_ti_data(ioc_type, raw_data)

    if not LLM_API_URL:
        logger.warning("LLM_API_URL non défini dans .env")
        return _fallback(ti_data, reason="LLM_API_URL manquant")

    try:
        resp = requests.post(
            f"{LLM_API_URL}/enrich",
            json=ti_data,
            timeout=600,
            headers={
                "Content-Type":             "application/json",
                "ngrok-skip-browser-warning": "true"
            }
        )
        resp.raise_for_status()
        result = resp.json()

        result["fallback"]   = False

        logger.info(f"LLM OK — {ti_data.get('indicator')} ({ioc_type}) "
                    f"→ {result.get('threat_level')}")
        return result

    except requests.exceptions.Timeout:
        logger.warning("[LLM] Timeout 240s")
        return _fallback(ti_data, reason="timeout 240s")   # ← était: {"error": ..., "fallback": True}

    except requests.exceptions.ConnectionError:
        logger.warning("[LLM] Colab/ngrok inaccessible")
        return _fallback(ti_data, reason="Colab/ngrok inaccessible")

    except Exception as e:
        logger.error(f"[LLM] Erreur inattendue: {e}")
        return _fallback(ti_data, reason=str(e))
    
# ── envoie données TI  +  contexte RAG au LLM  ───────────────────────────────────
def enrich_with_rag(ioc: str, ioc_type: str, final_verdict: str, rag_docs: list, ti_data: dict = {}) -> dict:
    import json
    ti_data = {**ti_data, "type": ioc_type}

    if not LLM_API_URL:
        return {"error": "LLM_API_URL manquant"}

    rag_preamble = (
        "RAG policy: les extraits ci-dessous sont un enrichissement secondaire. "
        "Les données TI structurées du payload sont la source d'autorité principale. "
        "Ne jamais contredire les champs TI (score, verdict, alertes, SPF/DMARC/DKIM, détections). "
        "Si les TI sont bénins, conserver une conclusion bénigne et factuelle.\n\n"
    )
    context_block = rag_preamble + "\n".join(
        f"[{r['source']}] (score={r['score']}) {r['text']}"
        for r in rag_docs
    ) if rag_docs else "Aucune donnée interne disponible."

    payload = {
        "indicator":     ioc,
        "type":          ioc_type,
        "rag_context":   context_block,
        "final_verdict": final_verdict,
    }

    # ── IP ────────────────────────────────────────────────
    if ioc_type == "ip":
        payload.update({
            "vt_malicious_count":  ti_data.get("vt_malicious_count", 0),
            "vt_total_engines":    ti_data.get("vt_total_engines", 0),
            "vt_verdict":          ti_data.get("vt_verdict", "unknown"),
            "vt_malware_families": ti_data.get("vt_malware_families", []),
            "abuseipdb_score":     ti_data.get("abuseipdb_score", 0),
            "otx_pulse_count":     ti_data.get("otx_pulse_count", 0),
            "country":             ti_data.get("country", "unknown"),
        })
        vt_mal = ti_data.get("vt_malicious_count", 0)
        abuse  = ti_data.get("abuseipdb_score", 0)
        fv     = str(final_verdict).strip().lower()
        if fv == "suspicious":
            payload["triage_note"] = (
                "Verdict TI = suspicious. "
                "threat_level must be at most medium. "
                "Avoid high/critical without explicit malicious evidence."
            )
        elif vt_mal == 0 and abuse < 20:
            payload["triage_note"] = (
                "VirusTotal shows 0 malicious detections and AbuseIPDB score is low. "
                "Final verdict is Clean. "
                "threat_level MUST be low or clean. "
                "Write a clear summary: this IP shows no known malicious activity "
                "and appears legitimate based on available threat intelligence."
            )

    # ── HASH ──────────────────────────────────────────────
    elif ioc_type == "hash":
        payload.update({
            "vt_malicious_count":   ti_data.get("vt_malicious_count", 0),
            "vt_suspicious":        ti_data.get("vt_suspicious", 0),
            "file_type":            ti_data.get("file_type", "unknown"),
            "vt_reputation":        ti_data.get("vt_reputation", 0),
            "otx_pulse_count":      ti_data.get("otx_pulse_count", 0),
            "otx_malware_families": ti_data.get("otx_malware_families", []),
            "mitre_attack":         ti_data.get("mitre_attack", []),
        })
        vt_mal = ti_data.get("vt_malicious_count", 0)
        fv     = str(final_verdict).strip().lower()
        if vt_mal == 0:
            payload["triage_note"] = (
                "VirusTotal shows 0 malicious detections. "
                "Final verdict is Clean. "
                "The RAG context contains generic rules that do NOT apply here. "
                "threat_level MUST be low or clean. "
                "Write a clear summary: file analyzed by multiple AV engines, "
                "no malicious behavior detected, file is considered benign, "
                "no action required."
            )
        elif fv == "suspicious":
            payload["triage_note"] = (
                "Verdict TI = suspicious. "
                "threat_level must be at most medium. "
                "Avoid high/critical without explicit malicious evidence."
            )

    # ── DOMAIN ────────────────────────────────────────────
    elif ioc_type == "domain":
        payload.update({
            "vt_malicious_count": ti_data.get("vt_malicious_count", 0),
            "vt_suspicious":      ti_data.get("vt_suspicious", 0),
            "vt_reputation":      ti_data.get("vt_reputation", 0),
            "global_risk_level":  ti_data.get("global_risk_level", "unknown"),
            "global_risk_score":  ti_data.get("global_risk_score"),
            "registrar":          ti_data.get("registrar", "unknown"),
        })
        vt_mal = ti_data.get("vt_malicious_count", 0)
        grs    = ti_data.get("global_risk_score") or 0
        if vt_mal == 0 and grs <= 10:
            payload["triage_note"] = (
                "VirusTotal shows 0 malicious detections and global risk score is 0. "
                "Final verdict is Clean. "
                "threat_level MUST be low or clean. "
                "Write a clear summary: domain has no known malicious association, "
                "appears legitimate based on threat intelligence, no action required."
            )

    # ── URL ───────────────────────────────────────────────
    elif ioc_type == "url":
        payload.update({
            "vt_malicious_count": ti_data.get("vt_malicious_count", 0),
            "vt_suspicious":      ti_data.get("vt_suspicious", 0),
            "vt_verdict":         ti_data.get("vt_verdict", "unknown"),
            "gsb_verdict":        ti_data.get("gsb_verdict", "unknown"),
            "phishtank_verdict":  ti_data.get("phishtank_verdict", "unknown"),
            "global_risk_level":  ti_data.get("global_risk_level", "unknown"),
        })
        vt_mal = ti_data.get("vt_malicious_count", 0)
        gsb    = str(ti_data.get("gsb_verdict", "")).lower()
        if vt_mal == 0 and gsb != "malicious":
            payload["triage_note"] = (
                "VirusTotal shows 0 malicious detections and GSB verdict is clean. "
                "threat_level MUST be low or clean. "
                "Write a clear summary: URL has no confirmed malicious association "
                "based on VirusTotal and Google Safe Browsing analysis."
            )

    # ── MAIL ──────────────────────────────────────────────
    elif ioc_type == "mail":
        alerts       = ti_data.get("mxtoolbox_alerts") or ti_data.get("alerts", [])
        spf_status   = _normalize_mail_auth_status(ti_data.get("spf", ""))
        dmarc_status = _normalize_mail_auth_status(ti_data.get("dmarc", ""))
        dkim_status  = _normalize_mail_auth_status(ti_data.get("dkim", ""))
        score        = ti_data.get("score", ti_data.get("mxtoolbox_score", 0))
        verdict      = ti_data.get("final_verdict", ti_data.get("mxtoolbox_verdict", "unknown"))
        payload.update({
            "score":         score,
            "verdict":       verdict,
            "spf":           spf_status,
            "dmarc":         dmarc_status,
            "dkim":          dkim_status,
            "final_verdict": verdict,
            "alerts":        alerts,
            "triage_note": (
                "IMPORTANT TI-ONLY TRIAGE: use only factual TI fields. "
                "Do NOT infer authentication failure unless explicitly stated in alerts. "
                f"MXToolbox score={score}/100 — verdict={verdict} — "
                f"SPF={spf_status} — DMARC={dmarc_status} — DKIM={dkim_status} — "
                f"alerts={len(alerts)} — alerts_list={alerts}. "
                "If score >= 70 and alerts <= 3 and SPF/DMARC present "
                "then threat_level must be low or clean."
            ),
        })

    # ── CVE ───────────────────────────────────────────────
    elif ioc_type == "cve":
        payload.update({
            "cvss_score":  ti_data.get("cvss_score", "N/A"),
            "severity":    ti_data.get("severity", "unknown"),
            "description": ti_data.get("description", ""),
            "cwe":         ti_data.get("cwe", []),
        })
    
    try:
        resp = requests.post(
            f"{LLM_API_URL}/enrich",
            json=payload,
            timeout=240,
            headers={
                "Content-Type":               "application/json",
                "ngrok-skip-browser-warning": "true"
            }
        )
        resp.raise_for_status()
         # ── Parsing robuste — Gemma retourne parfois du JSON incomplet ──
        try:
            data = resp.json()
        except Exception:
            # Tentative de récupération depuis le texte brut
            import re
            raw_text = resp.text
            print(f"[DEBUG] Réponse brute (non-JSON) : {raw_text[:300]}")

            # Cherche threat_level dans le texte brut
            tl_match = re.search(r'"threat_level"\s*:\s*"(\w+)"', raw_text)
            sc_match = re.search(r'"score"\s*:\s*(\d+)', raw_text)
            su_match = re.search(r'"summary"\s*:\s*"([^"]+)"', raw_text)

            if tl_match:
                data = {
                    "threat_level": tl_match.group(1),
                    "score":        int(sc_match.group(1)) if sc_match else 50,
                    "summary":      su_match.group(1) if su_match else "Analysis based on TI signals.",
                    "tags":         [],
                    "recommandation": "Investigate further.",
                }
            else:
                return _fallback(ti_data, reason="réponse Colab non parseable")

        # Vérifie que threat_level est présent et non vide
        if not data.get("threat_level"):
            print(f"[DEBUG] threat_level manquant dans réponse Colab : {data}")
            return _fallback(ti_data, reason="threat_level absent dans réponse LLM")

        print(f"[DEBUG] Réponse Colab parsée : {json.dumps(data, indent=2)}")
        data["rag_used"] = True
        return data

    except requests.exceptions.Timeout:
        return _fallback(ti_data, reason="timeout 240s")
    except requests.exceptions.ConnectionError:
        return _fallback(ti_data, reason="Colab/ngrok inaccessible")
    except Exception as e:
        return _fallback(ti_data, reason=str(e))