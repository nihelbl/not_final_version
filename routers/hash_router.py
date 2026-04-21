from fastapi import APIRouter, Query
from services.hash_services import get_hash_report
from fastapi.responses import JSONResponse
import json

router = APIRouter()

@router.get("/")
def hash_lookup(param: str = Query(..., description="Hash value to enrich")):
    report = get_hash_report(param)

    formatted = {
        "Hash": report["hash"],
        "File Type": report["file_type"],
        "Reputation Score": report["reputation_score"],
        "First Submission": report["first_submission"],
        "Last Analysis": report["last_analysis"],
        "Metadata": report["metadata"],
        "Related IPs": report["related_ips"],
        "Detection": {
            "Malicious": report["detection"]["malicious"],
            "Suspicious": report["detection"]["suspicious"],
            "Undetected": report["detection"]["undetected"]
        },
        "MITRE ATT&CK": report.get("mitre_attack", []),  # <-- ajouté
        "OTX": {
            "Name": report["otx"].get("otx_name"),
            "Pulse Count": report["otx"].get("pulse_count"),
            "Reputation": report["otx"].get("reputation"),
            "Malware Families": report["otx"].get("malware_families")
        },
        "Risk": {
            "Score": report["risk_score"],
            "Level": report["risk_level"]
        },
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