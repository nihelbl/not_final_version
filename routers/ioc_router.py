from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from services.cve_service import get_cve_report
from services.llm_enricher import enrich_ioc, enrich_with_rag
from services.rag_gate import build_rag_query
from services.ioc_analysis import analyze_ioc
from rag.rag_retriever import retrieve
import re

router = APIRouter()

class IOCRequest(BaseModel):
    indicator: str


def detect_type(indicator: str) -> str:
    indicator = indicator.strip()
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', indicator):
        return 'ip'
    if re.match(r'^CVE-\d{4}-\d{4,}$', indicator.upper()):
        return 'cve'
    if re.match(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$', indicator):
        return 'hash'
    if re.match(r'^https?://', indicator):
        return 'url'
    if re.match(r'^[\w\.-]+@[\w\.-]+\.[a-z]{2,}$', indicator):
        return 'mail'
    if re.match(r'^[\w\.-]+\.[a-z]{2,}$', indicator):
        return 'domain'
    return 'unknown'


def _normalize_ti_cve(raw: dict, indicator: str, ioc_type: str) -> dict:
    ti = {"indicator": indicator, "type": ioc_type}
    risk = raw.get("risk", {})
    ti.update(
        {
            "cve_id": raw.get("cve_id"),
            "severity": raw.get("severity", "N/A"),
            "cvss_score": raw.get("cvss_score"),
            "cvss_vector": raw.get("cvss_vector"),
            "cwe": raw.get("cwe", []),
            "published": raw.get("published"),
            "risk_level": risk.get("level", "unknown"),
            "affected": raw.get("affected", []),
            "description": raw.get("description", ""),
        }
    )
    return ti


@router.post("/analyze")
def analyze(body: IOCRequest):
    indicator = body.indicator.strip()
    if not indicator:
        return JSONResponse({'error': 'Indicateur manquant'}, status_code=400)

    ioc_type = detect_type(indicator)

    if ioc_type not in ("ip", "domain", "hash", "url", "mail", "cve"):
        return JSONResponse(
            {"error": f"Type non supporté : {ioc_type}"},
            status_code=400,
        )

    if ioc_type in ("ip", "domain", "hash", "url", "mail"):
        try:
            payload = analyze_ioc(indicator, ioc_type)
        except Exception as e:
            return JSONResponse(
                {"error": f"Erreur collecte TI : {str(e)}"},
                status_code=500,
            )
        if "error" in payload:
            err = str(payload["error"])
            status = 500 if "réponse invalide" in err.lower() else 400
            return JSONResponse({"error": payload["error"]}, status_code=status)
        return payload

    # ── CVE : flux inchangé (hors périmètre ioc_analysis) ──
    try:
        raw = get_cve_report(indicator)
    except Exception as e:
        return JSONResponse(
            {"error": f"Erreur collecte TI : {str(e)}"},
            status_code=500,
        )
    if not raw or not isinstance(raw, dict):
        return JSONResponse(
            {"error": f"Service TI a retourné une réponse invalide pour {indicator}"},
            status_code=500,
        )
    if "error" in raw:
        return JSONResponse({"error": raw["error"]}, status_code=400)

    ti_data = _normalize_ti_cve(raw, indicator, ioc_type)
    final_verdict = raw.get("final_verdict") or raw.get("global_risk_level", "unknown")

    rag_docs: list = []
    rag_fetch_error: str | None = None
    try:
        rag_query = build_rag_query(ioc_type, raw, ti_data)
        rag_docs = retrieve(
            query=rag_query,
            k=5,
            min_score=0.52,
            ioc_type=ioc_type,
        )
    except Exception as e:
        rag_docs = []
        rag_fetch_error = str(e)
        print(f"[RAG] Erreur : {e}")


    try:
        if rag_docs:
            llm_result = enrich_with_rag(
                ioc=indicator,
                ioc_type=ioc_type,
                final_verdict=final_verdict,
                rag_docs=rag_docs,
                ti_data=ti_data,
            )
        else:
            llm_result = enrich_ioc(ioc_type, raw)

        if "error" in llm_result or not llm_result.get("threat_level"):
            print(f"[DEBUG] LLM error/null → fallback. Reason: {llm_result.get('error', 'threat_level null')}")
            from services.llm_enricher import _fallback

            llm_result = _fallback(ti_data, reason=llm_result.get("error", "réponse LLM incomplète"))
        print(f"[DEBUG] llm_result reçu: {llm_result}")
    except Exception as e:
        llm_result = {
            "threat_level": "unknown",
            "score": 0,
            "summary": f"LLM indisponible : {str(e)}",
            "tags": [],
            "recommandation": "Analyse manuelle requise.",
            "fallback": True,
        }

    return {
        "indicator": indicator,
        "type": ioc_type,
        "ti_data": {
            "source": raw.get("source"),
            "description": raw.get("description"),
            "severity": raw.get("severity"),
            "cvss_score": raw.get("cvss_score"),
            "cvss_v2_score": raw.get("cvss_v2_score"),
            "cvss_vector": raw.get("cvss_vector"),
            "published": raw.get("published"),
            "last_modified": raw.get("last_modified"),
            "cwe": raw.get("cwe", []),
            "affected": raw.get("affected", []),
            "references": raw.get("references", []),
            "final_verdict": raw.get("risk", {}).get("level"),
        },
        "rag_context": [
            {"text": r["text"], "source": r["source"], "score": r["score"]}
            for r in rag_docs
        ]
        if rag_docs
        else [],
        "llm_analysis": {
            "threat_level": llm_result.get("threat_level"),
            "score": llm_result.get("score"),
            "summary": llm_result.get("summary"),
            "tags": llm_result.get("tags", []),
            "recommended_action": llm_result.get("recommandation"),
            "model": llm_result.get("model_used"),
            "rag_used": llm_result.get("rag_used", False),
            "fallback": llm_result.get("fallback", False),
            "rag_fetch_error": rag_fetch_error,
        },
    }

@router.get("/debug-hash")
def debug_hash():
    from services.hash_services import get_hash_report
    raw = get_hash_report("1ac890ff8a824da863fbf28eb585438fd7654abd2653f8d49537fc27bce78704")
    from services.rag_gate import collect_ti_signals
    signals = collect_ti_signals("hash", raw)
    return {"raw_verdict": raw.get("risk_level"), "signals": signals, "vt_malicious": raw.get("detection", {}).get("malicious")}