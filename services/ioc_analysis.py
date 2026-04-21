from __future__ import annotations
from typing import Literal
from rag.rag_retriever import retrieve
from services.domain_service import get_domain_report
from services.hash_services import get_hash_report
from services.ip_service import check_ip_reputation
from services.llm_enricher import enrich_ioc, enrich_with_rag, _fallback
from services.mail_service import check_mail_reputation
from services.rag_gate import build_rag_query, collect_ti_signals
from services.url_service import get_url_report

Classification = Literal["CLEAN", "MALICIOUS", "SUSPECT", "UNKNOWN"]

_LEGIT_MAIL_DOMAINS = frozenset(
    (
        "gmail.com",
        "outlook.com",
        "hotmail.com",
        "yahoo.com",
        "live.com",
        "msn.com",
        "microsoft.com",
        "google.com",
        "icloud.com",
        "proton.me",
        "protonmail.com",
    )
)

_LEGIT_MAIL_PROVIDERS = frozenset(
    (
        "Google Workspace",
        "Microsoft 365",
        "Yahoo Mail",
    )
)

def _lower(s: object) -> str:
    return (str(s) if s is not None else "").strip().lower()


def _as_int(x: object, default: int = 0) -> int:
    try:
        if x is None:
            return default
        return int(x)
    except (TypeError, ValueError):
        return default


def _confidence_numeric(raw: dict) -> float:
    c = raw.get("confidence")
    if isinstance(c, (int, float)):
        return float(c)
    m = {"strong": 90.0, "moderate": 60.0, "weak": 30.0}
    return m.get(_lower(c), 50.0)


def _global_risk_score(raw: dict, ioc_type: str) -> int | None:
    t = _lower(ioc_type)
    if t == "url":
        v = raw.get("global_risk_score")
    elif t == "domain":
        v = raw.get("global_risk_score")
    elif t == "hash":
        v = raw.get("global_risk_score")
    else:
        v = raw.get("global_risk_score")
    if v is None:
        return None
    return _as_int(v, -1) if v != "" else None


def _verdict_for_type(raw: dict, ioc_type: str) -> str:
    t = _lower(ioc_type)
    if t == "domain":
        return _lower(raw.get("global_risk_level") or raw.get("final_verdict"))
    if t == "hash":
        return _lower(raw.get("risk_level") or raw.get("global_risk_level"))
    if t == "url":
        return _lower(raw.get("final_verdict") or raw.get("global_risk_level"))
    if t == "mail":
        return _lower(raw.get("verdict"))
    return _lower(raw.get("final_verdict"))


def _ip_vt_malicious(raw: dict) -> int:
    stats = (raw.get("virustotal") or {}).get("stats") or {}
    return _as_int(stats.get("malicious"))


def _ip_vt_reputation(raw: dict) -> int:
    return _as_int((raw.get("virustotal") or {}).get("reputation"))


def _hash_vt_malicious(raw: dict) -> int:
    det = raw.get("detection") or {}
    return _as_int(det.get("malicious"))


def _url_vt_malicious(raw: dict) -> int:
    vt = (raw.get("vendors") or {}).get("virustotal") or {}
    return _as_int(vt.get("malicious"))


def _vt_malicious_count(raw: dict, ioc_type: str) -> int:
    t = _lower(ioc_type)
    if t == "ip":
        return _ip_vt_malicious(raw)
    if t == "domain":
        return _as_int((raw.get("virustotal") or {}).get("detection", {}).get("malicious"))
    if t == "hash":
        return _hash_vt_malicious(raw)
    if t == "url":
        return _url_vt_malicious(raw)
    return 0


def _vt_verdict_clean(raw: dict, ioc_type: str) -> bool:
    """VirusTotal (ou agrégat équivalent) considéré comme bénin — pour la règle unknown→clean."""
    t = _lower(ioc_type)
    if t == "ip":
        return _lower((raw.get("virustotal") or {}).get("verdict")) == "clean"
    if t == "domain":
        vt = raw.get("virustotal") or {}
        det = vt.get("detection") or {}
        if _as_int(det.get("malicious")) > 0:
            return False
        rl = _lower(vt.get("risk_level", ""))
        return rl in ("clean", "low", "none")
    if t == "hash":
        if _hash_vt_malicious(raw) > 0:
            return False
        rl = _lower(raw.get("risk_level", ""))
        return rl in ("clean", "low", "undetected")
    if t == "url":
        vt = (raw.get("vendors") or {}).get("virustotal") or {}
        if _as_int(vt.get("malicious")) > 0:
            return False
        return _lower(vt.get("verdict")) == "clean"
    return True


def _must_use_llm_rule2(raw: dict, ioc_type: str) -> bool:
    """Verdict / score / détections qui imposent LLM + RAG (non skip)."""
    t = _lower(ioc_type)
    gv = _verdict_for_type(raw, t)
    if gv in ("malicious", "high", "suspicious", "suspect", "douteux"):
        return True
    grs = _global_risk_score(raw, t)
    if grs is not None and grs > 50:
        return True
    if _vt_malicious_count(raw, t) > 0:
        return True
    return False


def should_skip_llm_entirely(raw: dict, ioc_type: str) -> bool:
    """
    Règle 1 (CLEAN) + règle 3 (unknown + score 0 + VT clean).
    Jamais True si la règle 2 exige le LLM.
    """
    if _must_use_llm_rule2(raw, ioc_type):
        return False

    t = _lower(ioc_type)
    gv = _verdict_for_type(raw, t)
    vm = _vt_malicious_count(raw, t)
    grs = _global_risk_score(raw, t)
    conf = _confidence_numeric(raw)

    if gv == "unknown":
        if (grs is None or grs == 0) and _vt_verdict_clean(raw, t):
            return True
        return False

    if gv in ("clean", "fiable"):
        return True

    if gv in ("low", "undetected") and vm == 0:
        return True

    if (
        grs is not None
        and grs == 0
        and gv
        not in ("suspicious", "suspect", "douteux", "malicious", "high", "unknown")
    ):
        return True

    if _vt_verdict_clean(raw, t):
        return True

    if conf >= 90 and vm == 0:
        return True

    if t == "mail":
        if gv == "fiable":
            return True
        if _mail_domain_legit(raw) and gv not in ("suspect", "douteux"):
            return True

    if t == "domain" and gv in ("clean", "low") and vm == 0:
        return True

    return False


def _non_clean_display_bucket(raw: dict, ioc_type: str) -> Classification:
    gv = _verdict_for_type(raw, _lower(ioc_type))
    if gv in ("malicious", "high"):
        return "MALICIOUS"
    if gv in ("suspicious", "suspect", "douteux"):
        return "SUSPECT"
    return "UNKNOWN"


def _mail_domain_legit(raw: dict) -> bool:
    dom = _lower(raw.get("domaine") or raw.get("domain"))
    if dom in _LEGIT_MAIL_DOMAINS:
        return True
    prov = raw.get("fournisseur")
    return prov in _LEGIT_MAIL_PROVIDERS


def get_threat_intelligence(indicator: str, indicator_type: str) -> dict:
    t = _lower(indicator_type)
    if t == "ip":
        return check_ip_reputation(indicator)
    if t == "domain":
        return get_domain_report(indicator)
    if t == "hash":
        return get_hash_report(indicator)
    if t == "url":
        return get_url_report(indicator)
    if t == "mail":
        return check_mail_reputation(indicator)
    raise ValueError(f"Type TI non supporté : {indicator_type}")


def normalize_ti(raw: dict, indicator: str, ioc_type: str) -> dict:
    """Aligné sur l'ancien _normalize_ti du routeur (payload Gemma / RAG)."""
    ti: dict = {"indicator": indicator, "type": ioc_type}
    if ioc_type == "ip":
        vt = raw.get("virustotal", {})
        abuse = raw.get("abuseipdb", {})
        otx = raw.get("otx", {})
        stats = vt.get("stats", {})
        ti.update(
            {
                "country": vt.get("country", "unknown"),
                "vt_verdict": vt.get("verdict", "unknown"),
                "vt_malicious_count": stats.get("malicious", 0),
                "vt_total_engines": sum(stats.values()) if stats else 0,
                "vt_malware_families": vt.get("tags", []),
                "abuseipdb_score": abuse.get("abuse_score", 0),
                "otx_pulse_count": otx.get("pulse_count", 0),
                "otx_verdict": otx.get("verdict", "unknown"),
            }
        )
    elif ioc_type == "domain":
        vt = raw.get("virustotal", {})
        det = vt.get("detection", {})
        mal = det.get("malicious", 0)
        sus = det.get("suspicious", 0)
        undet = det.get("undetected", 0)
        ht = raw.get("hackertarget", {})
        ti.update(
            {
                "vt_verdict": vt.get("risk_level", "unknown"),
                "vt_malicious_count": mal,
                "vt_suspicious": sus,
                "vt_reputation": vt.get("reputation_score", 0),
                "vt_malware_families": list(vt.get("categories", {}).values())[:3],
                "subdomains_count": ht.get("subdomains_count", 0),
                "registrar": raw.get("registrar", "unknown"),
                "creation_date": raw.get("creation_date", "unknown"),
                "ip_address": raw.get("ip_address", "unknown"),
                "global_risk_level": raw.get("global_risk_level", "unknown"),
                "global_risk_score": raw.get("global_risk_score"),
            }
        )
    elif ioc_type == "hash":
        det = raw.get("detection", {})
        otx = raw.get("otx", {})
        mal = raw.get("detection", {}).get("malicious") or 0
        sus = raw.get("detection", {}).get("suspicious") or 0
        und = raw.get("detection", {}).get("undetected") or 0
        ti.update(
            {
                "vt_verdict": raw.get("risk_level", "unknown"),
                "vt_malicious_count": mal,
                "vt_total_engines": (mal or 0) + (sus or 0) + (und or 0),
                "vt_reputation": raw.get("reputation_score", 0),
                "file_type": raw.get("file_type", "unknown"),
                "first_submission": raw.get("first_submission", "unknown"),
                "mitre_attack": [f["technique_name"] for f in (raw.get("mitre_attack") or [])[:3]],
                "otx_pulse_count": otx.get("pulse_count", 0),
                "otx_malware_families": otx.get("malware_families", []),
            }
        )
    elif ioc_type == "url":
        vt = raw.get("vendors", {}).get("virustotal", {})
        gsb = raw.get("vendors", {}).get("google_safe_browsing", {})
        pt = raw.get("vendors", {}).get("phishtank", {})
        ti.update(
            {
                "domain": raw.get("domain", "unknown"),
                "ip": raw.get("ip", "unknown"),
                "vt_malicious_count": vt.get("malicious", 0),
                "vt_suspicious": vt.get("suspicious", 0),
                "vt_verdict": vt.get("verdict", "unknown"),
                "gsb_verdict": gsb.get("verdict", "unknown"),
                "gsb_threats": gsb.get("threats", []),
                "phishtank_verdict": pt.get("verdict", "unknown"),
                "phishtank_verified": pt.get("verified", False),
                "final_verdict": raw.get("final_verdict", "unknown"),
                "global_risk_level": raw.get("global_risk_level", "unknown"),
                "global_risk_score": raw.get("global_risk_score"),
            }
        )
    elif ioc_type == "mail":
        score = raw.get("score", 100)
        ti.update(
            {
                "mxtoolbox_verdict": raw.get("verdict", "fiable"),
                "mxtoolbox_score": score,
                "mxtoolbox_alerts": raw.get("alertes", [])[:3],
                "mail_provider": raw.get("fournisseur", "unknown"),
                "spf": raw.get("spf", "N/A"),
                "dmarc": raw.get("dmarc", "N/A"),
                "mx_count": len(raw.get("mx", [])),
                "final_verdict": raw.get("verdict", "unknown"),
            }
        )
    return ti


def classify_indicator(raw: dict, indicator_type: str) -> Classification:
    """CLEAN = pas de LLM ; sinon libellé TI pour l'UI (MALICIOUS / SUSPECT / UNKNOWN)."""
    if should_skip_llm_entirely(raw, indicator_type):
        return "CLEAN"
    return _non_clean_display_bucket(raw, indicator_type)


def build_clean_response(raw: dict, ti_data: dict, ioc_type: str) -> dict:
    gv = _verdict_for_type(raw, ioc_type)
    parts = [f"Verdict TI : {gv}."]
    if ioc_type == "domain" and raw.get("global_risk_score") is not None:
        parts.append(f"Score de risque global : {raw.get('global_risk_score')}.")
    if ioc_type == "ip":
        parts.append("Sources : VirusTotal, AbuseIPDB, OTX — indicateur classé bénin par la TI.")
    summary = " ".join(parts)
    return {
        "threat_level": "clean",
        "score": 0,
        "summary": summary,
        "tags": [],
        "recommandation": "Aucune action urgente requise d'après les flux Threat Intelligence.",
        "model_used": None,
        "rag_used": False,
        "fallback": False,
        "sources_ti": ti_data.get("sources_ti"),
    }


def _apply_ip_suspicious_severity_cap(raw: dict, ioc_type: str, llm_result: dict) -> dict:
    """Verdict TI = suspicious : plafonner high/critical → medium (évite surestimation)."""
    if _lower(ioc_type) != "ip":
        return llm_result
    if _lower(raw.get("final_verdict", "")) != "suspicious":
        return llm_result
    out = dict(llm_result)
    tl = _lower(out.get("threat_level", ""))
    if tl in ("high", "critical"):
        out["threat_level"] = "medium"
        sc = out.get("score")
        if isinstance(sc, (int, float)) and sc > 55:
            out["score"] = min(55, int(sc))
    return out


def _enriched_ti_for_llm(ioc_type: str, raw: dict, ti_norm: dict) -> dict:
    """Complète normalize_ti avec les champs attendus par enrich_with_rag."""
    out = {**ti_norm, "type": ioc_type}
    if ioc_type == "domain":
        out.setdefault("global_risk_score", raw.get("global_risk_score"))
    if ioc_type == "mail":
        out["score"] = raw.get("score", out.get("mxtoolbox_score", 0))
        out["final_verdict"] = raw.get("verdict", "unknown")
        out["alerts"] = raw.get("alertes", [])
    if ioc_type == "hash":
        out["otx_malware_families"] = (raw.get("otx") or {}).get("malware_families", [])
        out["mitre_attack"] = raw.get("mitre_attack", [])
    return out


def _run_llm_with_rag(
    indicator: str,
    ioc_type: str,
    raw: dict,
    ti_norm: dict,
    final_verdict: str,
) -> tuple[list, bool, str | None, str | None, dict]:
    """
    Triage non-CLEAN : toujours tenter RAG (rag_skipped=False côté API),
    puis LLM — pas de gate « TI bénin » ici (évite rag_skip=True sur malicieux).
    """
    ti_signals = collect_ti_signals(ioc_type, raw)
    rag_docs: list = []
    rag_fetch_error: str | None = None
    skip_rag = False
    rag_gate_reason: str | None = None
    print(f"[RAG] Triage LLM — signaux TI: {ti_signals}")
    try:
        rag_query = build_rag_query(ioc_type, raw, ti_norm)
        rag_docs = retrieve(
            query=rag_query,
            k=5,
            min_score=0.35,
            ioc_type=ioc_type,
        )

        verdict = _verdict_for_type(raw, ioc_type)
        vt_malicious = _vt_malicious_count(raw, ioc_type)
        
         # APRÈS — garde quelques docs même pour un clean, pour contextualiser Gemma
        if verdict in ("clean", "low", "undetected") and vt_malicious == 0:
         BENIGN_KEYWORDS = [
         "benign", "legitimate", "false positive", "trusted",
         "clean", "safe", "low risk", "triage", "whitelist",
         "undetected", "no detection"]
         filtered = [
         doc for doc in rag_docs
         if any(kw in doc["text"].lower() for kw in BENIGN_KEYWORDS)]
         # Si aucun doc bénin → garde les 2 premiers pour que Gemma ait du contexte
         # mais on ajoutera une note triage dans le prompt
         rag_docs = filtered if filtered else rag_docs[:2]

        elif vt_malicious > 0:
         CLEAN_KEYWORDS = [
          "clean verdict", "zero malicious", "0 malicious",
          "benign", "no action required", "not malicious",
          "no confirmed threat", "classify as clean"]
         rag_docs = [
         doc for doc in rag_docs
         if not any(kw in doc["text"].lower() for kw in CLEAN_KEYWORDS)]

        if ioc_type == "mail":
         NEGATIVE_ONLY = ["suspicious", "phishing", "malicious", "urgency", "impersonation"]
         POSITIVE_HINT = ["legitimate", "benign", "trusted", "clean", "valid spf", "valid dmarc"]
         cleaned = [
             doc for doc in rag_docs
             if not all(kw in doc["text"].lower() for kw in NEGATIVE_ONLY[:2])
             or any(kw in doc["text"].lower() for kw in POSITIVE_HINT) ]
         rag_docs = cleaned if cleaned else rag_docs[:2]  # garde max 2 docs si tout négatif

    except Exception as e:
        rag_docs = []
        rag_fetch_error = str(e)
        print(f"[RAG] Erreur : {e}")

    ti_llm = _enriched_ti_for_llm(ioc_type, raw, ti_norm)
    if rag_docs:
        llm_result = enrich_with_rag(
            ioc=indicator,
            ioc_type=ioc_type,
            final_verdict=final_verdict,
            rag_docs=rag_docs,
            ti_data=ti_llm,
        )
    else:
        llm_result = enrich_ioc(ioc_type, raw)

    if "error" in llm_result or not llm_result.get("threat_level"):
        print(f"[DEBUG] LLM error/null → fallback. Reason: {llm_result.get('error', 'threat_level null')}")
        llm_result = _fallback(ti_llm, reason=llm_result.get("error", "réponse LLM incomplète"))

    llm_result = _apply_ip_suspicious_severity_cap(raw, ioc_type, llm_result)

    return rag_docs, skip_rag, rag_gate_reason, rag_fetch_error, llm_result


def api_ti_section(ioc_type: str, raw: dict) -> dict:
    """Bloc `ti_data` de la réponse HTTP (inchangé pour les clients)."""
    if ioc_type == "ip":
        return {
            "country": raw.get("virustotal", {}).get("country"),
            "asn": raw.get("virustotal", {}).get("asn"),
            "as_owner": raw.get("virustotal", {}).get("as_owner"),
            "reputation": raw.get("virustotal", {}).get("reputation"),
            "vt_verdict": raw.get("virustotal", {}).get("verdict"),
            "vt_stats": raw.get("virustotal", {}).get("stats"),
            "vt_votes": raw.get("virustotal", {}).get("votes"),
            "vt_tags": [t for t in raw.get("virustotal", {}).get("tags", []) if t != "no tags"],
            "vt_relations": {k: v for k, v in raw.get("virustotal", {}).get("relations", {}).items() if v},
            "abuseipdb": raw.get("abuseipdb"),
            "otx": raw.get("otx"),
            "talos": raw.get("talos"),
            "final_verdict": raw.get("final_verdict"),
        }
    if ioc_type == "domain":
        return {
            "ip_address": raw.get("ip_address"),
            "registrar": raw.get("registrar"),
            "creation_date": raw.get("creation_date"),
            "vt_verdict": raw.get("virustotal", {}).get("risk_level"),
            "vt_detection": raw.get("virustotal", {}).get("detection"),
            "vt_reputation": raw.get("virustotal", {}).get("reputation_score"),
            "subdomains": raw.get("hackertarget", {}).get("subdomains", []),
            "subdomains_count": raw.get("hackertarget", {}).get("subdomains_count", 0),
            "global_risk_score": raw.get("global_risk_score"),
            "confidence": raw.get("confidence"),
            "final_verdict": raw.get("global_risk_level"),
        }
    if ioc_type == "hash":
        return {
            "file_type": raw.get("file_type"),
            "first_submission": raw.get("first_submission"),
            "reputation": raw.get("reputation_score"),
            "vt_detection": raw.get("detection"),
            "mitre_attack": raw.get("mitre_attack", []),
            "otx": raw.get("otx", {}),
            "final_verdict": raw.get("risk_level"),
        }
    if ioc_type == "url":
        return {
            "domain": raw.get("domain"),
            "ip": raw.get("ip"),
            "scan_time": raw.get("scan_time"),
            "virustotal": raw.get("vendors", {}).get("virustotal"),
            "google_safe_browsing": raw.get("vendors", {}).get("google_safe_browsing"),
            "phishtank": raw.get("vendors", {}).get("phishtank"),
            "global_risk_score": raw.get("global_risk_score"),
            "confidence": raw.get("confidence"),
            "final_verdict": raw.get("final_verdict"),
        }
    if ioc_type == "mail":
        return {
            "domain": raw.get("domaine"),
            "mx": raw.get("mx", []),
            "spf": raw.get("spf"),
            "dmarc": raw.get("dmarc"),
            "fournisseur": raw.get("fournisseur"),
            "alertes": raw.get("alertes", []),
            "score": raw.get("score"),
            "final_verdict": raw.get("verdict"),
        }
    return {}


def analyze_ioc(indicator: str, indicator_type: str, force_rag: bool = False) -> dict:
    """
    Collecte TI, classifie, retourne le corps JSON prêt pour /analyze
    (sans CVE — le routeur gère CVE à part).
    """
    indicator = indicator.strip()
    ioc_type = _lower(indicator_type)
    raw = get_threat_intelligence(indicator, ioc_type)


    if not raw or not isinstance(raw, dict):
        return {"error": f"Service TI a retourné une réponse invalide pour {indicator}"}
    if "error" in raw:
        return {"error": raw["error"]}
    
    # ── NOUVEAU : enrichissement domain pour les emails ──
    domain_signals: dict = {}
    if ioc_type == "mail" and "@" in indicator:
        try:
            domain_part = indicator.split("@")[1]
            raw_domain = get_domain_report(domain_part)
            if raw_domain and isinstance(raw_domain, dict) and "error" not in raw_domain:
                domain_signals = collect_ti_signals("domain", raw_domain)
                print(f"[MAIL→DOMAIN] {domain_part} signals: {domain_signals}")
        except Exception as e:
            print(f"[MAIL→DOMAIN] Erreur enrichissement domain: {e}")
    # ────────────────────────────────────────────────────

    ti_norm = normalize_ti(raw, indicator, ioc_type)
    classification = classify_indicator(raw, ioc_type)
    final_verdict = raw.get("final_verdict") or raw.get("global_risk_level", "unknown")


    # Injecter les signaux domain dans ti_norm pour le LLM
    if domain_signals:
        ti_norm["domain_vt_malicious"] = domain_signals.get("vt_malicious", 0)
        ti_norm["domain_verdict"]      = domain_signals.get("verdict", "unknown")
        ti_norm["domain_risk_score"]   = domain_signals.get("global_risk_score", 0)
        # Si le domaine est malveillant → forcer classification MALICIOUS
        if domain_signals.get("vt_malicious", 0) > 0:
            classification = "MALICIOUS"
        
    sources_map = {
        "ip": ["VirusTotal", "AbuseIPDB", "OTX"],
        "hash": ["VirusTotal", "OTX"],
        "domain": ["VirusTotal", "HackerTarget"],
        "url": ["VirusTotal", "GoogleSafeBrowsing", "PhishTank"],
        "mail": ["MXToolbox"],
    }
    ti_norm["sources_ti"] = sources_map.get(ioc_type, ["VirusTotal"])

    rag_docs: list = []
    skip_rag = False
    rag_gate_reason: str | None = None
    rag_fetch_error: str | None = None

    if classification == "CLEAN" and not force_rag:
        llm_result = build_clean_response(raw, ti_norm, ioc_type)
        skip_rag = True
        rag_gate_reason = "ti_clean_skip_llm"
        rag_docs = []
    else:
        try:
            rag_docs, skip_rag, rag_gate_reason, rag_fetch_error, llm_result = _run_llm_with_rag(
                indicator, ioc_type, raw, ti_norm, str(final_verdict)
            )
        except Exception as e:
            llm_result = {
                "threat_level": "unknown",
                "score": 0,
                "summary": f"LLM indisponible : {str(e)}",
                "tags": [],
                "recommandation": "Analyse manuelle requise.",
                "fallback": True,
            }
    if ioc_type == "mail":
        mail_score = raw.get("score", 0)
        mail_verdict = _lower(raw.get("verdict", ""))
        n_alerts = len(raw.get("alertes", []))
        print(f"[MAIL DEBUG] score={mail_score} verdict={mail_verdict} alerts={n_alerts}")
        if domain_signals.get("vt_malicious", 0) > 0:
             print(f"[MAIL] Domain malveillant vt_malicious={domain_signals['vt_malicious']} → force high")
             llm_result["threat_level"] = "high"
             llm_result["score"] = max(80, llm_result.get("score", 80))
        if mail_score >= 50 or mail_verdict in ("fiable", "clean", "low") and n_alerts <= 3 and domain_signals.get("vt_malicious", 0) == 0:
            tl = _lower(llm_result.get("threat_level", ""))
            if tl in ("high", "critical", "medium"):
                print(f"[MAIL] Cap LLM {tl}→low")
                llm_result["threat_level"] = "low"
                llm_result["score"] = min(25, llm_result.get("score", 25))
    # ── Post-processing hash ──────────────────────────────
    elif ioc_type == "hash":
        vt_mal = _hash_vt_malicious(raw)
        tl = _lower(llm_result.get("threat_level", ""))
        if vt_mal == 0 and tl in ("high", "critical", "medium"):
            # Aucune détection VT → Gemma sur-classe, on plafonne
            print(f"[HASH] Cap {tl}→low (vt_malicious=0)")
            llm_result["threat_level"] = "low"
            llm_result["score"] = min(20, llm_result.get("score", 20))
        elif vt_mal > 20 and tl in ("low", "clean"):
            # Beaucoup de détections → Gemma sous-classe, on force
            print(f"[HASH] Force high (vt_malicious={vt_mal})")
            llm_result["threat_level"] = "high"
            llm_result["score"] = max(75, llm_result.get("score", 75))

    # ── Post-processing domain ────────────────────────────
    elif ioc_type == "domain":
        vt_mal = _as_int(
            (raw.get("virustotal") or {}).get("detection", {}).get("malicious")
        )
        grs = _global_risk_score(raw, "domain") or 0
        tl = _lower(llm_result.get("threat_level", ""))
        if vt_mal == 0 and grs <= 10 and tl in ("high", "critical"):
            print(f"[DOMAIN] Cap {tl}→low (vt_mal=0, grs={grs})")
            llm_result["threat_level"] = "low"
            llm_result["score"] = min(20, llm_result.get("score", 20))
        elif vt_mal > 3 and tl in ("low", "clean"):
            print(f"[DOMAIN] Force high (vt_mal={vt_mal})")
            llm_result["threat_level"] = "high"
            llm_result["score"] = max(75, llm_result.get("score", 75))

    # ── Post-processing URL ───────────────────────────────
    elif ioc_type == "url":
        vt_mal = _url_vt_malicious(raw)
        gsb = _lower(
            (raw.get("vendors") or {}).get("google_safe_browsing", {}).get("verdict", "")
        )
        tl = _lower(llm_result.get("threat_level", ""))
        if vt_mal == 0 and gsb != "malicious" and tl in ("high", "critical"):
            print(f"[URL] Cap {tl}→low (vt_mal=0, gsb={gsb})")
            llm_result["threat_level"] = "low"
            llm_result["score"] = min(20, llm_result.get("score", 20))
        elif (vt_mal > 3 or gsb == "malicious") and tl in ("low", "clean"):
            print(f"[URL] Force high (vt_mal={vt_mal}, gsb={gsb})")
            llm_result["threat_level"] = "high"
            llm_result["score"] = max(75, llm_result.get("score", 75))

    # ── Post-processing IP ────────────────────────────────
    # (déjà géré par _apply_ip_suspicious_severity_cap plus haut,
    #  on ajoute juste le cas vt_mal=0)
    elif ioc_type == "ip":
        vt_mal = _ip_vt_malicious(raw)
        abuse  = _as_int((raw.get("abuseipdb") or {}).get("abuse_score", 0))
        tl = _lower(llm_result.get("threat_level", ""))
        if vt_mal == 0 and abuse < 20 and tl in ("high", "critical"):
            print(f"[IP] Cap {tl}→low (vt_mal=0, abuse={abuse})")
            llm_result["threat_level"] = "low"
            llm_result["score"] = min(25, llm_result.get("score", 25))

    rag_context = (
        [{"text": r["text"], "source": r["source"], "score": r["score"]} for r in rag_docs] if rag_docs else []
    )

    return {
        "indicator": indicator,
        "type": ioc_type,
        "ti_data": api_ti_section(ioc_type, raw),
        "ioc_classification": classification,
        "rag_context": rag_context,
        "llm_analysis": {
            "threat_level": llm_result.get("threat_level"),
            "score": llm_result.get("score"),
            "summary": llm_result.get("summary"),
            "tags": llm_result.get("tags", []),
            "recommended_action": llm_result.get("recommandation"),
            "model": llm_result.get("model_used"),
            "rag_used": llm_result.get("rag_used", False),
            "fallback": llm_result.get("fallback", False),
            "rag_skipped": skip_rag,
            "rag_skip_reason": rag_gate_reason if skip_rag else None,
            "rag_fetch_error": rag_fetch_error,
            "ti_only": classification == "CLEAN",
        },
    }
