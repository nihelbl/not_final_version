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
# MITRE ATT&CK Static Mapping
# =========================
MITRE_FAMILY_MAP = {
    # Ransomware
    "ransomware":    [{"technique_id": "T1486", "technique_name": "Data Encrypted for Impact"},
                      {"technique_id": "T1490", "technique_name": "Inhibit System Recovery"}],
    "wannacry":      [{"technique_id": "T1486", "technique_name": "Data Encrypted for Impact"},
                      {"technique_id": "T1210", "technique_name": "Exploitation of Remote Services"}],
    "ryuk":          [{"technique_id": "T1486", "technique_name": "Data Encrypted for Impact"},
                      {"technique_id": "T1489", "technique_name": "Service Stop"}],
    "lockbit":       [{"technique_id": "T1486", "technique_name": "Data Encrypted for Impact"},
                      {"technique_id": "T1083", "technique_name": "File and Directory Discovery"}],
    "conti":         [{"technique_id": "T1486", "technique_name": "Data Encrypted for Impact"},
                      {"technique_id": "T1021", "technique_name": "Remote Services"}],

    # Trojans / RATs
    "trojan":        [{"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter"},
                      {"technique_id": "T1055", "technique_name": "Process Injection"}],
    "rat":           [{"technique_id": "T1219", "technique_name": "Remote Access Software"},
                      {"technique_id": "T1105", "technique_name": "Ingress Tool Transfer"}],
    "njrat":         [{"technique_id": "T1219", "technique_name": "Remote Access Software"},
                      {"technique_id": "T1547", "technique_name": "Boot or Logon Autostart Execution"}],
    "bladabindi":    [{"technique_id": "T1219", "technique_name": "Remote Access Software"},
                      {"technique_id": "T1547", "technique_name": "Boot or Logon Autostart Execution"}],
    "asyncrat":      [{"technique_id": "T1219", "technique_name": "Remote Access Software"},
                      {"technique_id": "T1055", "technique_name": "Process Injection"}],
    "remcos":        [{"technique_id": "T1219", "technique_name": "Remote Access Software"},
                      {"technique_id": "T1082", "technique_name": "System Information Discovery"}],
    "nanocore":      [{"technique_id": "T1219", "technique_name": "Remote Access Software"},
                      {"technique_id": "T1560", "technique_name": "Archive Collected Data"}],
    "darkcomet":     [{"technique_id": "T1219", "technique_name": "Remote Access Software"},
                      {"technique_id": "T1113", "technique_name": "Screen Capture"}],
    "quasar":        [{"technique_id": "T1219", "technique_name": "Remote Access Software"},
                      {"technique_id": "T1083", "technique_name": "File and Directory Discovery"}],
    "dcrat":         [{"technique_id": "T1219", "technique_name": "Remote Access Software"},
                      {"technique_id": "T1055", "technique_name": "Process Injection"}],

    # Stealers
    "stealer":       [{"technique_id": "T1555", "technique_name": "Credentials from Password Stores"},
                      {"technique_id": "T1056", "technique_name": "Input Capture"}],
    "redline":       [{"technique_id": "T1555", "technique_name": "Credentials from Password Stores"},
                      {"technique_id": "T1041", "technique_name": "Exfiltration Over C2 Channel"}],
    "raccoon":       [{"technique_id": "T1555", "technique_name": "Credentials from Password Stores"},
                      {"technique_id": "T1005", "technique_name": "Data from Local System"}],
    "vidar":         [{"technique_id": "T1555", "technique_name": "Credentials from Password Stores"},
                      {"technique_id": "T1083", "technique_name": "File and Directory Discovery"}],
    "formbook":      [{"technique_id": "T1056", "technique_name": "Input Capture"},
                      {"technique_id": "T1113", "technique_name": "Screen Capture"}],
    "agent tesla":   [{"technique_id": "T1056", "technique_name": "Input Capture"},
                      {"technique_id": "T1555", "technique_name": "Credentials from Password Stores"}],
    "agenttesla":    [{"technique_id": "T1056", "technique_name": "Input Capture"},
                      {"technique_id": "T1555", "technique_name": "Credentials from Password Stores"}],
    "lokibot":       [{"technique_id": "T1555", "technique_name": "Credentials from Password Stores"},
                      {"technique_id": "T1056", "technique_name": "Input Capture"}],
    "azorult":       [{"technique_id": "T1555", "technique_name": "Credentials from Password Stores"},
                      {"technique_id": "T1005", "technique_name": "Data from Local System"}],

    # Worms / Spreaders
    "worm":          [{"technique_id": "T1091", "technique_name": "Replication Through Removable Media"},
                      {"technique_id": "T1210", "technique_name": "Exploitation of Remote Services"}],
    "emotet":        [{"technique_id": "T1566", "technique_name": "Phishing"},
                      {"technique_id": "T1027", "technique_name": "Obfuscated Files or Information"},
                      {"technique_id": "T1071", "technique_name": "Application Layer Protocol"}],
    "mirai":         [{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"},
                      {"technique_id": "T1498", "technique_name": "Network Denial of Service"}],

    # Backdoors
    "backdoor":      [{"technique_id": "T1543", "technique_name": "Create or Modify System Process"},
                      {"technique_id": "T1071", "technique_name": "Application Layer Protocol"}],
    "cobalt strike": [{"technique_id": "T1055", "technique_name": "Process Injection"},
                      {"technique_id": "T1071", "technique_name": "Application Layer Protocol"},
                      {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter"}],
    "cobaltstrike":  [{"technique_id": "T1055", "technique_name": "Process Injection"},
                      {"technique_id": "T1071", "technique_name": "Application Layer Protocol"}],

    # Miners
    "miner":         [{"technique_id": "T1496", "technique_name": "Resource Hijacking"}],
    "xmrig":         [{"technique_id": "T1496", "technique_name": "Resource Hijacking"}],
    "coinminer":     [{"technique_id": "T1496", "technique_name": "Resource Hijacking"}],

    # Rootkits / Bootkits
    "rootkit":       [{"technique_id": "T1014", "technique_name": "Rootkit"},
                      {"technique_id": "T1542", "technique_name": "Pre-OS Boot"}],

    # Spyware / Adware
    "spyware":       [{"technique_id": "T1113", "technique_name": "Screen Capture"},
                      {"technique_id": "T1056", "technique_name": "Input Capture"}],
    "adware":        [{"technique_id": "T1176", "technique_name": "Browser Extensions"}],

    # Exploits / Droppers
    "exploit":       [{"technique_id": "T1203", "technique_name": "Exploitation for Client Execution"},
                      {"technique_id": "T1068", "technique_name": "Exploitation for Privilege Escalation"}],
    "dropper":       [{"technique_id": "T1105", "technique_name": "Ingress Tool Transfer"},
                      {"technique_id": "T1027", "technique_name": "Obfuscated Files or Information"}],
    "loader":        [{"technique_id": "T1055", "technique_name": "Process Injection"},
                      {"technique_id": "T1105", "technique_name": "Ingress Tool Transfer"}],

    # Generic
    "keylogger":     [{"technique_id": "T1056", "technique_name": "Input Capture"}],
    "downloader":    [{"technique_id": "T1105", "technique_name": "Ingress Tool Transfer"}],
    "banker":        [{"technique_id": "T1056", "technique_name": "Input Capture"},
                      {"technique_id": "T1555", "technique_name": "Credentials from Password Stores"}],
}


def map_mitre_from_names(name_sources: list) -> list:
    """
    Maps a list of strings (malware family names, AV detection names)
    to MITRE ATT&CK techniques. Deduplicates by technique_id.
    """
    seen_ids = set()
    mitre_techniques = []

    for entry in name_sources:
        if not entry:
            continue

        if isinstance(entry, dict):
            name = entry.get("display_name", "").lower()
        else:
            name = str(entry).lower()

        for keyword, techniques in MITRE_FAMILY_MAP.items():
            if keyword in name:
                for t in techniques:
                    if t["technique_id"] not in seen_ids:
                        seen_ids.add(t["technique_id"])
                        mitre_techniques.append({
                            **t,
                            "source": "detection name mapping",
                            "matched_on": name
                        })

    return mitre_techniques


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

    url     = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return {"error": "VirusTotal API error"}

    data = response.json()["data"]["attributes"]

    file_type        = data.get("type_description", "Unknown")
    reputation       = data.get("reputation", 0)
    first_submission = convert_timestamp(data.get("first_submission_date"))
    last_analysis    = convert_timestamp(data.get("last_analysis_date"))

    metadata = {
        "size":   data.get("size"),
        "md5":    data.get("md5"),
        "sha1":   data.get("sha1"),
        "sha256": data.get("sha256"),
        "magic":  data.get("magic")
    }

    stats      = data.get("last_analysis_stats", {})
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)

    # Extract AV detection names for MITRE mapping
    detection_names = []
    results = data.get("last_analysis_results", {})
    for av, result in results.items():
        if result.get("category") in ("malicious", "suspicious"):
            det_name = result.get("result") or ""
            if det_name:
                detection_names.append(det_name)

    # Related IPs / domains / URLs
    related_ips     = []
    ip_url          = f"https://www.virustotal.com/api/v3/files/{file_hash}/relationships/contacted_ips"
    related_domains = get_vt_relationships(file_hash, "contacted_domains")
    related_urls    = get_vt_relationships(file_hash, "contacted_urls")
    ip_response     = requests.get(ip_url, headers=headers)
    if ip_response.status_code == 200:
        ip_data     = ip_response.json().get("data", [])
        related_ips = [ip["id"] for ip in ip_data]

    return {
        "file_type":        file_type,
        "reputation":       reputation,
        "first_submission": first_submission,
        "last_analysis":    last_analysis,
        "metadata":         metadata,
        "malicious":        malicious,
        "suspicious":       suspicious,
        "undetected":       undetected,
        "related_ips":      related_ips,
        "related_domains":  related_domains,
        "related_urls":     related_urls,
        "detection_names":  detection_names,   # <-- noms AV pour MITRE
    }


def get_vt_relationships(file_hash, relation_type):
    url     = f"https://www.virustotal.com/api/v3/files/{file_hash}/relationships/{relation_type}"
    headers = {"x-apikey": VT_API_KEY}

    response = requests.get(url, headers=headers)
    results  = []

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

    url     = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return {"error": "OTX API error"}

    data = response.json()

    # Extraire aussi les tags des pulses pour enrichir le mapping MITRE
    pulse_tags = []
    for pulse in data.get("pulse_info", {}).get("pulses", []):
        pulse_tags.extend(pulse.get("tags", []))
        pulse_tags.append(pulse.get("name", ""))

    return {
        "pulse_count":      data.get("pulse_info", {}).get("count", 0),
        "reputation":       data.get("reputation", 0),
        "malware_families": data.get("malware_families", []),
        "otx_name":         data.get("name", "N/A"),
        "pulse_tags":       pulse_tags,
    }


# =========================
# MAIN FUNCTION
# =========================
def get_hash_report(file_hash):
    vt_data  = virustotal_hash(file_hash)
    otx_data = otx_hash_enrichment(file_hash)

    # Combiner toutes les sources pour le mapping MITRE :
    # 1. malware_families OTX
    # 2. tags des pulses OTX
    # 3. noms de détection AV depuis VT
    all_name_sources = (
        otx_data.get("malware_families", [])
        + otx_data.get("pulse_tags", [])
        + vt_data.get("detection_names", [])
    )
    mitre_attack = map_mitre_from_names(all_name_sources)

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
    db       = SessionLocal()
    new_scan = ScanHistory(
        indicator  = file_hash,
        risk_level = risk_level,
        risk_score = risk_score,
        confidence = confidence,
        source     = "VirusTotal + OTX"
    )
    db.add(new_scan)
    db.commit()
    db.close()

    return {
        "hash":               file_hash,
        "file_type":          vt_data.get("file_type"),
        "reputation_score":   vt_data.get("reputation"),
        "first_submission":   vt_data.get("first_submission"),
        "last_analysis":      vt_data.get("last_analysis"),
        "metadata":           vt_data.get("metadata"),
        "mitre_attack":       mitre_attack,
        "detection": {
            "malicious":  vt_data.get("malicious"),
            "suspicious": vt_data.get("suspicious"),
            "undetected": vt_data.get("undetected")
        },
        "relations": {
            "ips":     vt_data.get("related_ips"),
            "domains": vt_data.get("related_domains"),
            "urls":    vt_data.get("related_urls")
        },
        "otx":               otx_data,
        "risk_score":        risk_score,
        "risk_level":        risk_level,
        "global_risk_score": global_score,
        "global_risk_level": global_level,
        "confidence":        confidence,
    }