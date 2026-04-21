import requests
import os
from dotenv import load_dotenv
from datetime import datetime
from database.db import SessionLocal
from database.models import ScanHistory

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")


# =========================
# Utilities
# =========================
def convert_timestamp(ts):
    if ts:
        return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    return None


# =========================
# Risk Calculations
# =========================
def calculate_risk(malicious, suspicious, reputation):
    score = ((malicious or 0) * 5) + ((suspicious or 0) * 3) + abs(reputation or 0)
    if score == 0:
        level = "Clean"
    elif score <= 20:
        level = "Low"
    elif score <= 50:
        level = "Medium"
    else:
        level = "High"
    return level, score


def calculate_global_risk(vt_malicious, vt_suspicious, otx_score, otx_rep):
    vt_malicious  = vt_malicious  or 0
    vt_suspicious = vt_suspicious or 0
    otx_score     = otx_score     or 0
    otx_rep       = otx_rep       or 0

    vt_component  = (vt_malicious * 4) + (vt_suspicious * 2)
    otx_component = (otx_score * 5) + abs(otx_rep)
    global_score  = vt_component + otx_component

    if global_score == 0:
        level = "Clean"
    elif global_score <= 50:
        level = "Low"
    elif global_score <= 150:
        level = "Medium"
    else:
        level = "High"

    if vt_malicious > 0 and otx_score > 0:
        confidence = "Strong"
    elif vt_malicious > 0 or otx_score > 0:
        confidence = "Moderate"
    else:
        confidence = "Weak"

    return global_score, level, confidence


# =========================
# VirusTotal
# =========================
def virustotal_hash(file_hash):
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not found in .env"}

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return {"error": "VirusTotal API error"}

    data = response.json()["data"]["attributes"]

    # Basic info
    file_type = data.get("type_description", "Unknown")
    reputation = data.get("reputation", 0)
    first_submission = convert_timestamp(data.get("first_submission_date"))
    last_analysis = convert_timestamp(data.get("last_analysis_date"))

    # Metadata
    metadata = {
        "size": data.get("size"),
        "md5": data.get("md5"),
        "sha1": data.get("sha1"),
        "sha256": data.get("sha256"),
        "magic": data.get("magic")
    }

    # Detection stats
    stats = data.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)

    # MITRE ATT&CK
    mitre_attack = []
    results = data.get("last_analysis_results", {})
    for av, result in results.items():
        if "mitre_attack" in result:
            for mitre in result["mitre_attack"]:
                mitre_attack.append({
                    "av": av,
                    "technique_id": mitre.get("technique_id"),
                    "technique_name": mitre.get("technique_name")
                })

    # Related IPs
    related_ips = [] 
    ip_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/relationships/contacted_ips"
    
    related_domains = get_vt_relationships(file_hash, "contacted_domains")
    related_urls = get_vt_relationships(file_hash, "contacted_urls")
    ip_response = requests.get(ip_url, headers=headers)
    if ip_response.status_code == 200:
        ip_data = ip_response.json().get("data", [])
        related_ips = [ip["id"] for ip in ip_data]

    return {
        "file_type": file_type,
        "reputation": reputation,
        "first_submission": first_submission,
        "last_analysis": last_analysis,
        "metadata": metadata,
        "malicious": malicious,
        "suspicious": suspicious,
        "undetected": undetected,
        "related_ips": related_ips,
        "related_domains": related_domains,
        "related_urls": related_urls,
        "mitre_attack": mitre_attack
    }

def get_vt_relationships(file_hash, relation_type):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}/relationships/{relation_type}"
    headers = {"x-apikey": VT_API_KEY}

    response = requests.get(url, headers=headers) 

    results = []
    if response.status_code == 200:
        data = response.json().get("data", [])
        for item in data:
            attrs = item.get("attributes", {})
            if relation_type == "contacted_domains":
                results.append(attrs.get("hostname"))
            elif relation_type == "contacted_urls":
                results.append(attrs.get("url"))
            else:
                results.append(item.get("id"))
    return [r for r in results if r] 
# =========================
# OTX
# =========================
def otx_hash_enrichment(file_hash):
    if not OTX_API_KEY:
        return {"error": "OTX API key not found in .env"}

    url = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return {"error": "OTX API error"}

    data = response.json()
    return {
        "pulse_count": data.get("pulse_info", {}).get("count", 0),
        "reputation": data.get("reputation", 0),
        "malware_families": data.get("malware_families", []),
        "otx_name": data.get("name", "N/A")
    }


# =========================
# MAIN FUNCTION
# =========================
def get_hash_report(file_hash):
    vt_data = virustotal_hash(file_hash)
    otx_data = otx_hash_enrichment(file_hash)

    risk_level, risk_score = calculate_risk(
        vt_data.get("malicious", 0),
        vt_data.get("suspicious", 0),
        vt_data.get("reputation", 0)
    )

    global_score, global_level, confidence = calculate_global_risk(
        vt_data.get("malicious", 0),
        vt_data.get("suspicious", 0),
        otx_data.get("pulse_count", 0),
        otx_data.get("reputation", 0)
    )

    # Save to database
    db = SessionLocal()
    new_scan = ScanHistory(
        indicator=file_hash,
        risk_level=risk_level,
        risk_score=risk_score,
        confidence=confidence,
        source="VirusTotal + OTX"
    )
    db.add(new_scan)
    db.commit()
    db.close()

    return {
        "hash": file_hash,
        "file_type": vt_data.get("file_type"),
        "reputation_score": vt_data.get("reputation"),
        "first_submission": vt_data.get("first_submission"),
        "last_analysis": vt_data.get("last_analysis"),
        "metadata": vt_data.get("metadata"),
        "related_ips": vt_data.get("related_ips"),
        "mitre_attack": vt_data.get("mitre_attack"),  # <-- MITRE ATT&CK ajouté
        "detection": {
            "malicious": vt_data.get("malicious"),
            "suspicious": vt_data.get("suspicious"),
            "undetected": vt_data.get("undetected")
        },
        "relations": {
            "ips": vt_data.get("related_ips"),
            "domains": vt_data.get("related_domains"),
            "urls": vt_data.get("related_urls")
},
        "otx": otx_data,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "global_risk_score": global_score,
        "global_risk_level": global_level,
        "confidence": confidence,
    }