from fastapi import APIRouter, Query
from services.domain_service import get_domain_report
from fastapi.responses import JSONResponse
import json

router = APIRouter()
@router.get("/")
def domain_lookup(
    param: str = Query(..., description="Domain name to enrich")
):
    report = get_domain_report(param)

    if "error" in report:
        return JSONResponse(
            content={"error": report["error"]},
            status_code=404
        )

    formatted = {
        "Domain": report["domain"],
        "IP Address": report["ip_address"],        
        "Registrar": report["registrar"],
        "Creation Date": report["creation_date"],

        # --- SOURCE : VIRUSTOTAL ---
        "VirusTotal": {
            "Reputation Score": report["virustotal"]["reputation_score"],
            "Detection": {
                "Malicious": report["virustotal"]["detection"]["malicious"],
                "Suspicious": report["virustotal"]["detection"]["suspicious"],
                "Undetected": report["virustotal"]["detection"]["undetected"]
            },
            "Last Analysis Date": report["virustotal"]["last_analysis_date"],
            "Risk Score": report["virustotal"]["risk_score"],
            "Risk Level": report["virustotal"]["risk_level"]
        },

        # --- SOURCE : HACKERTARGET ---
        "HackerTarget": {
            "Subdomains"      : report["hackertarget"]["subdomains"],
            "Subdomains Count": report["hackertarget"]["subdomains_count"]
},

        # --- RISK GLOBAL ---
        "Global Risk": {
            "Score": report["global_risk_score"],
            "Level": report["global_risk_level"],
            "Confidence": report["confidence"]
        }
    }

    return JSONResponse(
        content=json.loads(json.dumps(formatted, indent=4)),
        media_type="application/json"
    )