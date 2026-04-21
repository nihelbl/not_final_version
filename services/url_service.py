import requests
import os
import urllib.parse
import ipaddress
import socket
from dotenv import load_dotenv
from datetime import datetime
from database.db import SessionLocal
from database.models import ScanHistory


load_dotenv()
VT_API_KEY        = os.getenv("VT_API_KEY")
GOOGLE_SB_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

TIMEOUT = 15


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# -------------------- VIRUSTOTAL --------------------
import base64
import time

def virustotal_url_scan(url: str) -> dict:
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not found"}
    
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        #récupère via ID base64 (pas de quota submit)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=TIMEOUT
        )

        # Si pas dans VT soumet et attend
        if resp.status_code == 404:
            time.sleep(15)
            submit = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
                data={"url": url},
                timeout=TIMEOUT
            )
            if submit.status_code == 429:
                return {"error": "VT rate limit — réessaie dans 1 minute"}
            if submit.status_code != 200:
                return {"error": f"VT submission failed: {submit.status_code}"}
            
            time.sleep(10)  # attend l'analyse
            analysis_id = submit.json()["data"]["id"]
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=TIMEOUT
            )

        if resp.status_code == 429:
            return {"error": "VT rate limit — réessaie dans 1 minute"}
        
        if resp.status_code != 200:
            return {"error": f"VT error: {resp.status_code}"}

        attrs = resp.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        verdict = "malicious"  if malicious > 3 else \
                  "suspicious" if malicious > 0 or suspicious > 0 else "clean"

        return {
            "verdict"   : verdict,
            "malicious" : malicious,
            "suspicious": suspicious,
            "undetected": stats.get("undetected", 0),
            "harmless"  : stats.get("harmless", 0)
        }

    except Exception as e:
        return {"error": str(e)}


# -------------------- GOOGLE SAFE BROWSING --------------------
def google_safe_browsing_scan(url: str) -> dict:
    if not GOOGLE_SB_API_KEY:
        return {"error": "Google Safe Browsing API key not found"}
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SB_API_KEY}"
        payload = {
            "client": {"clientId": "TIP", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING",
                                     "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes":    ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries":    [{"url": url}]
            }
        }
        resp = requests.post(endpoint, json=payload, timeout=TIMEOUT)
        if resp.status_code != 200:
            return {"error": f"GSB error: {resp.status_code}"}

        data = resp.json()
        matches = data.get("matches", [])

        if matches:
            threat_types = list({m["threatType"] for m in matches})
            return {
                "verdict":      "malicious",
                "threats":      threat_types,
                "match_count":  len(matches)
            }
        return {"verdict": "clean", "threats": [], "match_count": 0}

    except Exception as e:
        return {"error": str(e)}


# -------------------- PHISHTANK --------------------
def phishtank_scan(url: str) -> dict:
    try:
        resp = requests.post(          # ← POST obligatoire
            "https://checkurl.phishtank.com/checkurl/",
            data={
                "url":    urllib.parse.quote(url, safe=""),
                "format": "json",
                "app_key": os.getenv("PHISHTANK_API_KEY", "")
            },
            headers={"User-Agent": "phishtank/TIP"},
            timeout=TIMEOUT
        )
        if not resp.text.strip():      # ← réponse vide
            return {"verdict": "unknown", "error": "empty response"}
        if resp.status_code != 200:
            return {"error": f"PhishTank error: {resp.status_code}"}

        data        = resp.json().get("results", {})
        in_database = data.get("in_database", False)
        verified    = data.get("verified", False)

        return {
            "verdict"    : "malicious"  if (in_database and verified) else
                           "suspicious" if in_database else "clean",
            "in_database": in_database,
            "verified"   : verified,
            "phish_id"   : data.get("phish_id")
        }
    except Exception as e:
        return {"verdict": "unknown", "error": str(e)}


# -------------------- RISK GLOBAL --------------------
def calculate_global_risk(vt: dict, gsb: dict, pt: dict) -> tuple:
    score = 0

    vt_mal = vt.get("malicious", 0)
    vt_sus = vt.get("suspicious", 0)
    score += (vt_mal * 4) + (vt_sus * 2)

    if gsb.get("verdict") == "malicious":
        score += 40

    if pt.get("verdict") == "malicious":
        score += 35
    elif pt.get("verdict") == "suspicious":
        score += 15

    #Si GSB dit malicious → score minimum 60 (high)
    if gsb.get("verdict") == "malicious":
        score = max(score, 60)

    #Si PT vérifié malicious → score minimum 70
    if pt.get("verdict") == "malicious" and pt.get("verified"):
        score = max(score, 70)

    score = min(100, score)

    level = ("critical" if score >= 80 else
             "high"     if score >= 60 else
             "medium"   if score >= 40 else
             "low"      if score >= 20 else "clean")

    sources_positive = sum([
        vt.get("verdict") == "malicious",
        gsb.get("verdict") == "malicious",
        pt.get("verdict") in ["malicious", "suspicious"]
    ])
    confidence = "Strong"  if sources_positive >= 2 else \
                 "Moderate" if sources_positive == 1 else "Weak"

    return score, level, confidence


# -------------------- MAIN --------------------
def get_url_report(url: str) -> dict:
    domain = urllib.parse.urlparse(url).netloc or url

    # Résolution IP
    try:
        ip_resolved = socket.gethostbyname(domain) \
                      if not is_ip_address(domain) else domain
    except Exception:
        ip_resolved = "Could not resolve"

    # Appels APIs
    vt_result  = virustotal_url_scan(url)
    gsb_result = google_safe_browsing_scan(url)
    pt_result  = phishtank_scan(url)

    score, level, confidence = calculate_global_risk(vt_result, gsb_result, pt_result)

    #Verdict final — logique correcte
    if gsb_result.get("verdict") == "malicious":
        final_verdict = "malicious"
    elif pt_result.get("verdict") == "malicious" and pt_result.get("verified"):
        final_verdict = "malicious"
    elif vt_result.get("verdict") == "malicious" and pt_result.get("verdict") == "malicious":
        final_verdict = "malicious"
    elif vt_result.get("verdict") == "malicious":
        final_verdict = "suspicious"
    elif vt_result.get("verdict") == "suspicious" or pt_result.get("verdict") == "suspicious":
        final_verdict = "suspicious"
    else:
        final_verdict = "clean"

    # Sauvegarde DB
    db = SessionLocal()
    db.add(ScanHistory(
        indicator=url,
        risk_level=level,
        risk_score=score,
        confidence=confidence,
        source="VirusTotal+GoogleSafeBrowsing+PhishTank"
    ))
    db.commit()
    db.close()

    return {
        "url"             : url,
        "domain"          : domain,
        "ip"              : ip_resolved,
        "type"            : "IP" if is_ip_address(domain) else "Domain",
        "scan_time"       : datetime.utcnow().isoformat(),
        "final_verdict"   : final_verdict,     
        "global_risk_score": score,
        "global_risk_level": level,
        "confidence"      : confidence,
        "vendors": {
            "virustotal"          : vt_result,
            "google_safe_browsing": gsb_result,
            "phishtank"           : pt_result
        },
    }