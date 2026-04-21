import requests
import os
import socket
from dotenv import load_dotenv
from datetime import datetime
from database.db import SessionLocal
from database.models import ScanHistory

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")


def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower()
    for prefix in ["https://", "http://"]:
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    if domain.startswith("www."):
        domain = domain[4:]
    domain = domain.split("/")[0]
    return domain


def resolve_ip(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return "N/A"


def calculate_risk(malicious, suspicious, reputation):
    reputation_penalty = abs(reputation) if reputation < 0 else 0
    score = (malicious * 5) + (suspicious * 3) + reputation_penalty
    if score == 0:     level = "Clean"
    elif score <= 20:  level = "Low"
    elif score <= 50:  level = "Medium"
    else:              level = "High"
    return level, score


def calculate_global_risk(vt_malicious, vt_suspicious, subdomain_count, vt_reputation=0):
    
    # Les détections VT sont le signal principal
    vt_component = (vt_malicious * 10) + (vt_suspicious * 4)
    
    # Sous-domaines = signal faible, SEULEMENT si combiné avec des détections
    # Un domaine légitime peut avoir des centaines de sous-domaines (microsoft, google...)
    sub_component = 0
    if vt_malicious > 0 and subdomain_count > 5:
        sub_component = min(subdomain_count * 0.5, 20)  # plafonné à 20

    # Réputation VT négative = signal supplémentaire
    rep_penalty = abs(vt_reputation) if vt_reputation < 0 else 0

    global_score = vt_component + sub_component + rep_penalty
    global_score = round(global_score)

    if global_score == 0:     level = "Clean"
    elif global_score <= 15:  level = "Low"
    elif global_score <= 40:  level = "Medium"
    else:                     level = "High"
    if vt_malicious > 5:
        confidence = "Strong"
    elif vt_malicious > 0 or vt_suspicious > 2:
        confidence = "Moderate"
    else:
        confidence = "Weak"

    return global_score, level, confidence


# ── HackerTarget ────────────────────────
def hackertarget_subdomains(domain: str) -> dict:
    try:
        resp = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=10
        )
        if resp.status_code != 200 or "error" in resp.text.lower():
            return {"subdomains": [], "count": 0}

        lines = [l.strip() for l in resp.text.splitlines() if l.strip()]
        subdomains = [l.split(",")[0] for l in lines if "," in l]
        return {
            "subdomains": subdomains[:10],
            "count"     : len(subdomains)
        }
    except Exception:
        return {"subdomains": [], "count": 0}


def get_domain_report(domain: str):
    domain     = normalize_domain(domain)
    ip_address = resolve_ip(domain)

    # ── VirusTotal ───────────────────────────────────────────
    url      = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers  = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    print("STATUS:", response.status_code)
    print("RESPONSE:", response.text)

    if response.status_code != 200:
        return {"error": "Domain not found or API error"}

    data       = response.json()["data"]["attributes"]
    stats      = data.get("last_analysis_stats", {})
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)

    risk_level, risk_score = calculate_risk(
        malicious, suspicious, data.get("reputation", 0)
    )

    # ── HackerTarget ─────────────────────────────────────────
    ht_data = hackertarget_subdomains(domain)

    global_score, global_level, confidence = calculate_global_risk(
    malicious, suspicious, ht_data["count"], data.get("reputation", 0)
)

    last_analysis_timestamp = data.get("last_analysis_date")
    last_analysis_date = (
        datetime.utcfromtimestamp(last_analysis_timestamp).strftime("%Y-%m-%d")
        if last_analysis_timestamp else "N/A"
    )

    creation_timestamp = data.get("creation_date")
    creation_date = (
        datetime.utcfromtimestamp(creation_timestamp).strftime("%Y-%m-%d")
        if creation_timestamp else "N/A"
    )

    # ── Sauvegarde DB ────────────────────────────────────────
    db = SessionLocal()
    db.add(ScanHistory(
        indicator=domain,
        risk_level=risk_level,
        risk_score=risk_score,
        confidence=confidence,
        source="VirusTotal+HackerTarget"
    ))
    db.commit()
    db.close()

    return {
        "domain"       : domain,
        "ip_address"   : ip_address,
        "registrar"    : data.get("registrar", "N/A"),
        "creation_date": creation_date,

        "virustotal": {
            "reputation_score"  : data.get("reputation", 0),
            "detection"         : {
                "malicious" : malicious,
                "suspicious": suspicious,
                "undetected": undetected
            },
            "last_analysis_date": last_analysis_date,
            "risk_score"        : risk_score,
            "risk_level"        : risk_level
        },
        "hackertarget": {
            "subdomains"      : ht_data["subdomains"],
            "subdomains_count": ht_data["count"]
        },

        "global_risk_score": global_score,
        "global_risk_level": global_level,
        "confidence"       : confidence,
    }