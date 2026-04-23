import json
import os
import uuid

import requests
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database.db import get_db
from database.models import Message
from routers.ioc_router import _normalize_ti_cve, detect_type
from services.cve_service import get_cve_report
from services.intent_classifier import classify_message
from services.ioc_analysis import analyze_ioc
from services.llm_enricher import enrich_ioc

LLM_API_URL = os.getenv("LLM_API_URL", "")
router = APIRouter()


class ChatMessage(BaseModel):
    message: str
    session_id: str | None = None


class BulkChatRequest(BaseModel):
    indicators: list[str]
    session_id: str | None = None


def _detect_language(text: str) -> str:
    """Détection simple basée sur des mots français courants."""
    french_markers = [
        "quoi", "comment", "pourquoi", "cest", "c'est", "qu'est",
        "quel", "quelle", "est-ce", "fonctionne", "explique",
        "définition", "veut dire", "kesako", "kézako",
        "signifie", "difference", "différence", "entre",
        "que", "des", "les", "une", "dans", "pour", "avec",
    ]
    text_lower = text.lower()
    if any(m in text_lower for m in french_markers):
        return "french"
    return "english"


def _answer_cybersec_question(question: str) -> str:
    if not LLM_API_URL:
        return "LLM unavailable. Please try again later."

    lang = _detect_language(question)

    # ✅ System prompt adapté à la langue
    if lang == "french":
        system = (
            "Tu es un expert en cybersécurité. "
            "Réponds OBLIGATOIREMENT en français. "
            "Ta réponse doit contenir 3 à 5 phrases complètes. "
            "Structure : définition → fonctionnement → exemple concret → recommandation. "
            "Ne t'arrête jamais au milieu d'une phrase. "
            "Ne réponds pas avec un seul mot."
        )
    else:
        system = (
            "You are a cybersecurity expert assistant. "
            "Answer in English with 3-5 complete sentences. "
            "Structure: definition → how it works → real example → recommendation. "
            "Never stop mid-sentence. Never reply with a single word."
        )

    try:
        resp = requests.post(
            f"{LLM_API_URL}/chat",
            json={"question": question, "system": system},
            timeout=240,
            headers={"ngrok-skip-browser-warning": "true",
                     "Accept-Charset": "utf-8" },
        )
        resp.raise_for_status()
        resp.encoding = 'utf-8'
        answer = resp.json().get("answer", "No answer returned.")

        # ✅ Fallback si réponse trop courte (1 mot)
        if len(answer.split()) < 10:
            return (
                "Désolé, je n'ai pas pu générer une réponse complète. "
                "Reformule ta question en anglais pour de meilleurs résultats."
                if lang == "french"
                else "Sorry, I could not generate a complete answer. Please rephrase."
            )

        return answer

    except Exception as e:
        return f"LLM error: {str(e)}"

# ── Response formatting ─────────────────────────────────────────────────────

def _format_response(indicator: str, ioc_type: str, raw_analysis: dict) -> dict:
    ti  = raw_analysis.get("ti_data", {}) or {}
    llm = raw_analysis.get("llm_analysis", {}) or {}

    verdict = {
        "threat_level":       llm.get("threat_level", "unknown"),
        "score":              llm.get("score", 0),
        "tags":               llm.get("tags", []),

    }

    t = ioc_type.lower()

    if t == "ip":
        vt_stats  = ti.get("vt_stats") or {}
        abuseipdb = ti.get("abuseipdb") or {}
        otx       = ti.get("otx") or {}
        relations = ti.get("vt_relations") or {}
        ti_summary = {
            "country": ti.get("country"),
            "asn":     ti.get("asn"),
            "isp":     ti.get("as_owner"),
            "reputation": {
                "virustotal": {
                    "malicious":  vt_stats.get("malicious", 0),
                    "suspicious": vt_stats.get("suspicious", 0),
                },
                "abuseipdb": {"score": abuseipdb.get("abuse_score", 0)},
                "otx":       {"pulses": otx.get("pulse_count", 0)},
            },
            "associated_domains": (relations.get("domains") or [])[:5],
            "associated_files":   (relations.get("files") or [])[:5],
        }

    elif t == "hash":
        vt_det = ti.get("vt_detection") or {}
        otx    = ti.get("otx") or {}
        ti_summary = {
            "file_type":  ti.get("file_type"),
            "first_seen": ti.get("first_submission"),
            "detection": {
                "virustotal": {
                    "malicious":  vt_det.get("malicious", 0),
                    "suspicious": vt_det.get("suspicious", 0),
                    "undetected": vt_det.get("undetected", 0),
                },
                "otx": {"pulses": otx.get("pulse_count", 0)},
            },
            "mitre_attack": (ti.get("mitre_attack") or [])[:3],
        }

    elif t == "domain":
        vt_det = ti.get("vt_detection") or {}
        ti_summary = {
            "ip":               ti.get("ip_address"),
            "registrar":        ti.get("registrar"),
            "created":          ti.get("creation_date"),
            "detection": {
                "virustotal": {"malicious": vt_det.get("malicious", 0),
                               "suspicious": vt_det.get("suspicious", 0)},
            },
            "subdomains_count":  ti.get("subdomains_count", 0),
            "global_risk_score": ti.get("global_risk_score", 0),
        }

    elif t == "url":
        vt  = ti.get("virustotal") or {}
        gsb = ti.get("google_safe_browsing") or {}
        pt  = ti.get("phishtank") or {}
        ti_summary = {
            "domain": ti.get("domain"),
            "ip":     ti.get("ip"),
            "detection": {
                "virustotal": {
                    "malicious":  vt.get("malicious", 0),
                    "suspicious": vt.get("suspicious", 0),
                },
                "google_safe_browsing": {
                    "threats": gsb.get("threats", []),
                },
                "phishtank": {"verdict": pt.get("verdict")},
            },
            "global_risk_score": ti.get("global_risk_score"),
        }

    elif t in ("mail", "email"):
        ti_summary = {
            "domain":   ti.get("domain"),
            "security": {
                "mx":    "present" if ti.get("mx") else "missing",
                "spf":   "present" if ti.get("spf") else "missing",
                "dmarc": "present" if ti.get("dmarc") else "missing",
            },
            "alerts":   ti.get("alertes") or [],
            "provider": ti.get("fournisseur"),
        }

    elif t == "cve":
        ti_summary = {
            "severity":    ti.get("severity"),
            "cvss_score":  ti.get("cvss_score"),
            "cvss_vector": ti.get("cvss_vector"),
            "cwe":         ti.get("cwe", []),
            "affected":    (ti.get("affected") or [])[:5],
            "published":   ti.get("published"),
        }

    else:
        ti_summary = ti

    return {
        "indicator":  indicator,
        "type":       ioc_type,
        "verdict":    verdict,
        "ti_summary": ti_summary,
    }

def _build_human_message(indicator: str, result: dict) -> str:
    llm = result.get("llm_analysis", {})
    threat_level = llm.get("threat_level", "unknown")
    summary = llm.get("summary", "")
    return (
        f" {summary}"
    )


_SEVERITY_ORDER = ["critical", "high", "medium", "low", "clean", "unknown"]


def _worst_verdict(results: list[dict]) -> str:
    found = set()
    for r in results:
        tl = (
            r.get("analysis", {}).get("llm_analysis", {}).get("threat_level", "unknown")
            or "unknown"
        )
        found.add(tl.lower())
    for level in _SEVERITY_ORDER:
        if level in found:
            return level
    return "unknown"

def _get_tl(r: dict) -> str:
    return (r.get("verdict", {}).get("threat_level", "") or "").lower()


def _analyze_one(indicator: str) -> dict:
    ioc_type = detect_type(indicator.strip())
    if ioc_type == "unknown":
        return {
            "indicator": indicator,
            "type": "unknown",
            "error": "Unrecognized indicator type.",
        }
    try:
        if ioc_type == "cve":
            raw = get_cve_report(indicator)
            if not raw or "error" in raw:
                return {
                    "indicator": indicator,
                    "type": ioc_type,
                    "error": raw.get("error", "CVE lookup failed."),
                }
            ti_data = _normalize_ti_cve(raw, indicator, ioc_type)
            llm_result = enrich_ioc(ioc_type, raw)
            return {
                "indicator": indicator,
                "type": ioc_type,
                "analysis": {"ti_data": ti_data, "llm_analysis": llm_result},
            }
        result = analyze_ioc(indicator.strip(), ioc_type)
        return {"indicator": indicator, "type": ioc_type, "analysis": result}
    except Exception as e:
        return {"indicator": indicator, "type": ioc_type, "error": str(e)}


@router.post("/message")
def chat_message(body: ChatMessage, db: Session = Depends(get_db)):
    message = body.message.strip()
    if not message:
        raise HTTPException(status_code=400, detail="Message cannot be empty.")

    session_id = body.session_id or str(uuid.uuid4())
    intent = classify_message(message)

    # Save user message
    db.add(Message(session_id=session_id, role="user", content=message))
    db.commit()

    # Off-topic
    if intent == "off_topic":
        reply = {
            "message": (
                "I am a cybersecurity assistant. I can analyze indicators "
                "(IPs, hashes, URLs, domains, emails, CVEs) and answer "
                "questions related to cybersecurity. "
                "Please ask me something in that domain."
            ),
        }
        db.add(Message(session_id=session_id, role="assistant", content=json.dumps(reply)))
        db.commit()
        return reply

    # Cybersec question
    if intent == "question":
        answer = _answer_cybersec_question(message)
        reply = { "message": answer}
        db.add(Message(session_id=session_id, role="assistant", content=json.dumps(reply)))
        db.commit()
        return reply

    # IOC analysis
    result = _analyze_one(message)
    if "error" in result and "analysis" not in result:
        raise HTTPException(status_code=400, detail=result["error"])

    raw_analysis = result.get("analysis", {})
    formatted    = _format_response(message, result["type"], raw_analysis)

    reply = {
        "message":    _build_human_message(message, raw_analysis),
        **formatted,
    }

    db.add(Message(session_id=session_id, role="assistant", content=json.dumps(reply)))
    db.commit()
    return reply


@router.post("/analyze/bulk")
def chat_bulk(body: BulkChatRequest, db: Session = Depends(get_db)):
    indicators = [i.strip() for i in body.indicators if i.strip()]

    if not indicators:
        raise HTTPException(status_code=400, detail="Indicator list is empty.")
    if len(indicators) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 indicators per request.")

    session_id = body.session_id or str(uuid.uuid4())

    db.add(Message(session_id=session_id, role="user", content=json.dumps(indicators)))
    db.commit()

    raw_results = [_analyze_one(ind) for ind in indicators]

    # Format chaque résultat
    formatted_results = []
    for r in raw_results:
        if "error" in r and "analysis" not in r:
            formatted_results.append({
                "indicator": r["indicator"],
                "type":      r.get("type", "unknown"),
                "error":     r["error"],
            })
        else:
            formatted_results.append(
                _format_response(r["indicator"], r["type"], r.get("analysis", {}))
            )

    malicious_levels = {"critical", "high", "medium"}
    clean_levels = {"low", "clean"}

    malicious_count = sum(1 for r in formatted_results if _get_tl(r) in malicious_levels)
    clean_count     = sum(1 for r in formatted_results if _get_tl(r) in clean_levels)
    error_count     = sum(1 for r in formatted_results if "error" in r)
    unknown_count   = len(indicators) - malicious_count - clean_count - error_count
    worst           = _worst_verdict(formatted_results)

    reply = {
        "summary": {
            "total":           len(indicators),
            "malicious_count": malicious_count,
            "clean_count":     clean_count,
            "unknown_count":   unknown_count + error_count,
            "worst_verdict":   worst,
            "human_summary": (
                f"{malicious_count} malicious out of {len(indicators)} "
                f"indicators analyzed. Worst verdict: {worst}."
            ),
        },
        "results": formatted_results,
    }

    db.add(Message(session_id=session_id, role="assistant", content=json.dumps(reply)))
    db.commit()
    return reply
