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
            timeout=60,
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


def _build_human_message(indicator: str, result: dict) -> str:
    llm = result.get("llm_analysis", {})
    threat_level = llm.get("threat_level", "unknown")
    summary = llm.get("summary", "")
    return (
        f"Analysis complete: `{indicator}` is classified as "
        f"**{threat_level}**. {summary}"
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
            "session_id": session_id,
            "intent": "off_topic",
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
        reply = {"session_id": session_id, "intent": "question", "message": answer}
        db.add(Message(session_id=session_id, role="assistant", content=json.dumps(reply)))
        db.commit()
        return reply

    # IOC analysis
    result = _analyze_one(message)
    if "error" in result and "analysis" not in result:
        raise HTTPException(status_code=400, detail=result["error"])

    human_msg = _build_human_message(message, result.get("analysis", {}))
    reply = {
        "session_id": session_id,
        "intent": "ioc",
        "indicator": message,
        "type": result["type"],
        "analysis": result.get("analysis", {}),
        "message": human_msg,
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

    results = [_analyze_one(ind) for ind in indicators]

    malicious_levels = {"critical", "high", "medium"}
    clean_levels = {"low", "clean"}

    def _get_tl(r):
        return (
            r.get("analysis", {}).get("llm_analysis", {}).get("threat_level", "") or ""
        ).lower()

    malicious_count = sum(1 for r in results if _get_tl(r) in malicious_levels)
    clean_count = sum(1 for r in results if _get_tl(r) in clean_levels)
    error_count = sum(1 for r in results if "error" in r and "analysis" not in r)
    unknown_count = len(indicators) - malicious_count - clean_count - error_count
    worst = _worst_verdict(results)

    reply = {
        "session_id": session_id,
        "summary": {
            "total": len(indicators),
            "malicious_count": malicious_count,
            "clean_count": clean_count,
            "unknown_count": unknown_count + error_count,
            "worst_verdict": worst,
            "human_summary": (
                f"{malicious_count} malicious out of {len(indicators)} "
                f"indicators analyzed. Worst verdict: {worst}."
            ),
        },
        "results": results,
    }

    db.add(Message(session_id=session_id, role="assistant", content=json.dumps(reply)))
    db.commit()
    return reply
