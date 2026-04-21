import requests
import ipaddress
import os
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

TIMEOUT = 10
# -------------------- VIRUSTOTAL --------------------
def check_virustotal(ip):
    if not VT_API_KEY:
        return {"error": "API key missing"}
    try:
        base_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(base_url, headers=headers, timeout=TIMEOUT)
        if response.status_code != 200:
            return {"error": f"http_{response.status_code}"}
        data = response.json()
        attr = data["data"]["attributes"]
        stats = attr.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        if malicious > 5:
            verdict = "malicious"
        elif malicious > 0 or suspicious > 0:
            verdict = "suspicious"
        else:
            verdict = "clean"
        #réseau
        country = attr.get("country")
        asn = attr.get("asn")
        as_owner = attr.get("as_owner")
        #Tags
        tags = attr.get("tags", [])
        if not tags:
            tags = ["no tags"]
        #Reputation
        reputation = attr.get("reputation", 0)
        #Votes
        votes = attr.get("total_votes", {})
        harmless_votes = votes.get("harmless", 0)
        malicious_votes = votes.get("malicious", 0)
        #Relations
        relations = {}
        try:
            files_url = f"{base_url}/communicating_files"
            res = requests.get(files_url, headers=headers, timeout=TIMEOUT)
            if res.status_code == 200:
                relations["files"] = [
                    f["id"] for f in res.json().get("data", [])[:5]
                ]
        except:
            relations["files"] = []
        try:
            urls_url = f"{base_url}/urls"
            res = requests.get(urls_url, headers=headers, timeout=TIMEOUT)
            if res.status_code == 200:
                relations["urls"] = [
                    u["id"] for u in res.json().get("data", [])[:5]
                ]
        except:
            relations["urls"] = []
        try:
            dns_url = f"{base_url}/resolutions"
            res = requests.get(dns_url, headers=headers, timeout=TIMEOUT)
            if res.status_code == 200:
                relations["domains"] = [
                    d["attributes"]["host_name"]
                    for d in res.json().get("data", [])[:5]
                ]
        except:
            relations["domains"] = []
        return {
            "verdict": verdict,
            "stats": stats,
            "country": country,
            "asn": asn,
            "as_owner": as_owner,
            "tags": tags,
            "reputation": reputation,
            "votes": {
                "harmless": harmless_votes,
                "malicious": malicious_votes
            },
            "relations": relations,
        }
    except Exception as e:
        return {"error": str(e)}

# -------------------- ABUSEIPDB --------------------
def check_abuseipdb(ip):
    if not ABUSE_API_KEY:
        return {"error": "API key missing"}
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip}
        response = requests.get(url, headers=headers, params=params, timeout=TIMEOUT)
        if response.status_code != 200:
            return {"error": f"http_{response.status_code}"}
        data = response.json()
        score = data["data"]["abuseConfidenceScore"]
        verdict = "clean"
        if score > 50:
            verdict = "malicious"
        elif score > 0:
            verdict = "suspicious"
        return {
            "verdict": verdict,
            "abuse_score": score
        }
    except Exception as e:
        return {"error": str(e)}
    
# -------------------- OTX --------------------
def check_otx(ip):
    if not OTX_API_KEY:
        return {"error": "API key missing"}
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code != 200:
            return {"error": f"http_{response.status_code}"}
        data = response.json()
        pulses = data.get("pulse_info", {}).get("count", 0)
        verdict = "suspicious" if pulses > 0 else "clean"
        return {
            "verdict": verdict,
            "pulse_count": pulses
        }
    except requests.exceptions.Timeout:
        return {"pulses": [], "pulse_count": 0, "error": "timeout"}   # ← fallback propre
    except requests.exceptions.ConnectionError:
        return {"pulses": [], "pulse_count": 0, "error": "unreachable"}
    except Exception as e:
        return {"pulses": [], "pulse_count": 0, "error": str(e)}

# -------------------- TALOS (Manual Lookup) --------------------
def check_talos(ip):
    return {
        "status": "manual_lookup_required",
        "url": f"https://talosintelligence.com/reputation_center/lookup?search={ip}"
    }

# -------------------- GLOBAL FUNCTION --------------------
def check_ip_reputation(param: str):

    # Validate IP
    try:
        ip_obj = ipaddress.ip_address(param)
    except ValueError:
        return {"error": "Invalid IP address"}

    #Détecte les IP privées/réservées
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
        return {
            "ip"           : param,
            "final_verdict": "clean",
            "info"         : "IP privée ou réservée — analyse externe non applicable",
            "network_type" : (
                "loopback"  if ip_obj.is_loopback else
                "private"   if ip_obj.is_private  else
                "reserved"
            )
        }
    result = {"ip": param}
    # Call vendors
    vt = check_virustotal(param)
    abuse = check_abuseipdb(param)
    otx = check_otx(param)
    talos = check_talos(param)
    result["virustotal"] = vt
    result["abuseipdb"] = abuse
    result["otx"] = otx
    result["talos"] = talos

    # -------- Final Verdict Logic --------
    malicious_count  = 0
    suspicious_count = 0

    for source in [vt, abuse, otx]:
      if isinstance(source, dict):
         if source.get("verdict") == "malicious":
             malicious_count += 1
         elif source.get("verdict") == "suspicious":
             suspicious_count += 1

    if malicious_count >= 2:
      final_verdict = "malicious"
    elif malicious_count == 1 or suspicious_count >= 2:
     final_verdict = "suspicious" 
    elif suspicious_count == 1:
     final_verdict = "low"
    else:
     final_verdict = "clean"
    result["final_verdict"] = final_verdict
    return result

