import requests
import os
import re
from dotenv import load_dotenv
from datetime import datetime
from database.db import SessionLocal
from database.models import ScanHistory

load_dotenv()

NVD_API_URL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CIRCL_API_URL = "https://cve.circl.lu/api/cve"
NVD_API_KEY   = os.getenv("NVD_API_KEY")
TIMEOUT       = 15


# -------------------- VALIDATION --------------------
def is_valid_cve(cve_id: str) -> bool:
    return bool(re.match(r'^CVE-\d{4}-\d{4,}$', cve_id.upper().strip()))


# -------------------- CPE PARSER --------------------
def parse_cpe(cpe: str) -> str:
    """Convertit cpe:2.3:a:apache:log4j:2.0 → Apache Log4j 2.0"""
    try:
        parts   = cpe.split(":")
        vendor  = parts[3].replace("_", " ").title()
        product = parts[4].replace("_", " ").title()
        version = parts[5] if len(parts) > 5 and parts[5] != "*" else ""
        return f"{vendor} {product} {version}".strip()
    except Exception:
        return cpe


# -------------------- DATE PARSER --------------------
def format_date(date_str: str) -> str:
    """2021-12-10T10:15:09.143 → 2021-12-10"""
    if not date_str or date_str == "N/A":
        return "N/A"
    try:
        return date_str.split("T")[0]
    except Exception:
        return date_str


# -------------------- REFERENCES FILTER --------------------
def filter_references(references: list) -> list:
    """Garde les références officielles en priorité"""
    priority_sources = [
        "nvd.nist.gov", "cisa.gov", "apache.org",
        "microsoft.com", "ubuntu.com", "redhat.com",
        "debian.org", "oracle.com", "github.com/advisories"
    ]
    refs_priority = [
        ref for ref in references
        if any(src in ref for src in priority_sources)
    ]
    # Si pas de références prioritaires → garde les 3 premières
    return refs_priority[:5] if refs_priority else references[:3]


# -------------------- NVD --------------------
def enrich_cve_nvd(cve_id: str) -> dict:
    headers = {"User-Agent": "Threat-Intel-Platform/1.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        response = requests.get(
            NVD_API_URL,
            headers=headers,
            params={"cveId": cve_id},
            timeout=TIMEOUT
        )

        if response.status_code == 429:
            return {"error": "NVD rate limit — réessaie dans 30s"}
        if response.status_code != 200:
            return {"error": f"NVD error: {response.status_code}"}

        data  = response.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {"error": "CVE non trouvé sur NVD"}

        cve = vulns[0]["cve"]

        # Description EN priorité
        descriptions = cve.get("descriptions", [])
        description  = next(
            (d["value"] for d in descriptions if d["lang"] == "en"),
            descriptions[0]["value"] if descriptions else "N/A"
        )

        metrics  = cve.get("metrics", {})
        cvss_v3  = (metrics.get("cvssMetricV31") or
                    metrics.get("cvssMetricV30") or [])
        cvss_v2  = metrics.get("cvssMetricV2", [])

        cvss_data    = cvss_v3[0]["cvssData"] if cvss_v3 else {}
        cvss_v2_data = cvss_v2[0]["cvssData"] if cvss_v2 else {}

        # Produits affectés — dédupliqués et formatés
        configurations = cve.get("configurations", [])
        affected_raw   = []
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    if cpe.get("vulnerable"):
                        affected_raw.append(cpe.get("criteria", ""))

        affected_clean = list(dict.fromkeys(
            parse_cpe(cpe) for cpe in affected_raw
        ))[:5]

        # CWE
        weaknesses = cve.get("weaknesses", [])
        cwes = []
        for w in weaknesses:
            for desc in w.get("description", []):
                if desc.get("value", "").startswith("CWE-"):
                    cwes.append(desc["value"])

        # Références filtrées
        all_refs    = [r["url"] for r in cve.get("references", [])]
        refs_clean  = filter_references(all_refs)

        return {
            "source"       : "NVD",
            "cve_id"       : cve.get("id"),
            "description"  : description,
            "severity"     : cvss_data.get("baseSeverity", "N/A"),
            "cvss_score"   : cvss_data.get("baseScore"),
            "cvss_vector"  : cvss_data.get("vectorString", "N/A"),
            "cvss_v2_score": cvss_v2_data.get("baseScore"),
            "published"    : format_date(cve.get("published")),
            "last_modified": format_date(cve.get("lastModified")),
            "cwe"          : cwes,
            "affected"     : affected_clean,
            "references"   : refs_clean,
        }

    except requests.exceptions.Timeout:
        return {"error": "NVD timeout"}
    except Exception as e:
        return {"error": str(e)}


# -------------------- CIRCL (fallback) --------------------
def enrich_cve_circl(cve_id: str) -> dict:
    try:
        resp = requests.get(
            f"{CIRCL_API_URL}/{cve_id}",
            timeout=TIMEOUT
        )
        if resp.status_code != 200:
            return {"error": f"CIRCL error: {resp.status_code}"}

        data = resp.json()
        if not data:
            return {"error": "CVE non trouvé sur CIRCL"}

        cvss_score = data.get("cvss")
        severity   = (
            "CRITICAL" if cvss_score and float(cvss_score) >= 9.0 else
            "HIGH"     if cvss_score and float(cvss_score) >= 7.0 else
            "MEDIUM"   if cvss_score and float(cvss_score) >= 4.0 else
            "LOW"      if cvss_score else "N/A"
        )

        # Références filtrées
        all_refs   = list(data.get("references", []))
        refs_clean = filter_references(all_refs)

        # Produits affectés
        affected_raw   = list(data.get("vulnerable_product", []))
        affected_clean = list(dict.fromkeys(
            parse_cpe(cpe) for cpe in affected_raw
        ))[:5]

        cwe = data.get("cwe")

        return {
            "source"       : "CIRCL",
            "cve_id"       : cve_id,
            "description"  : data.get("summary", "N/A"),
            "severity"     : severity,
            "cvss_score"   : cvss_score,
            "cvss_vector"  : data.get("cvss-vector", "N/A"),
            "cvss_v2_score": None,
            "published"    : format_date(data.get("Published")),
            "last_modified": format_date(data.get("Modified")),
            "cwe"          : [cwe] if cwe else [],
            "references"   : refs_clean,
        }

    except requests.exceptions.Timeout:
        return {"error": "CIRCL timeout"}
    except Exception as e:
        return {"error": str(e)}


# -------------------- RISK --------------------
def calculate_cve_risk(cvss_score) -> dict:
    if cvss_score is None:
        return {"level": "unknown", "score": 0, "color": "gray"}

    score = float(cvss_score)
    if score >= 9.0:
        return {"level": "critical", "score": score, "color": "red"}
    elif score >= 7.0:
        return {"level": "high",     "score": score, "color": "orange"}
    elif score >= 4.0:
        return {"level": "medium",   "score": score, "color": "yellow"}
    else:
        return {"level": "low",      "score": score, "color": "green"}


# -------------------- MAIN --------------------
def get_cve_report(cve_id: str) -> dict:
    cve_id = cve_id.upper().strip()

    if not is_valid_cve(cve_id):
        return {"error": f"Format CVE invalide : {cve_id} (attendu: CVE-YYYY-NNNNN)"}

    # 1. NVD en priorité
    result = enrich_cve_nvd(cve_id)

    # 2. CIRCL en fallback si NVD échoue
    if "error" in result:
        print(f"[CVE] NVD failed ({result['error']}) → fallback CIRCL")
        result = enrich_cve_circl(cve_id)

    if "error" in result:
        return result

    # 3. Risk level
    risk           = calculate_cve_risk(result.get("cvss_score"))
    result["risk"] = risk

    # 4. Sauvegarde DB
    try:
        db = SessionLocal()
        db.add(ScanHistory(
            indicator  = cve_id,
            risk_level = risk["level"],
            risk_score = int(risk["score"] * 10),
            confidence = "Strong" if result["source"] == "NVD" else "Moderate",
            source     = result["source"]
        ))
        db.commit()
        db.close()
    except Exception as e:
        print(f"[CVE] DB error: {e}")

    return result