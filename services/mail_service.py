import requests
import os
from dotenv import load_dotenv

load_dotenv()
MXTOOLBOX_API_KEY = os.getenv("MXTOOLBOX_API_KEY")
if not MXTOOLBOX_API_KEY:
    raise ValueError("API key MXToolbox manquante")
TIMEOUT = 10

def detect_provider(mx_list):
    """Détecte le fournisseur à partir des serveurs MX"""
    if not mx_list:
        return "Inconnu"
    mx_string = " ".join([mx["serveur"] for mx in mx_list]).lower()
    if "google" in mx_string:
        return "Google Workspace"
    elif "outlook" in mx_string or "protection.outlook.com" in mx_string:
        return "Microsoft 365"
    elif "zoho" in mx_string:
        return "Zoho Mail"
    elif "yahoo" in mx_string:
        return "Yahoo Mail"
    else:
        return "Autre"

def detect_suspicious_tld(domain):
    """Détecte les TLDs souvent utilisés pour du phishing"""
    suspicious_tlds = ['.vip', '.icu', '.cfd', '.xyz', '.club', '.top', '.gq', '.ml', '.bid', '.loan', '.date']
    tld = domain.split('.')[-1].lower()
    if tld in suspicious_tlds:
        return True, f"TLD suspect (.{tld})"
    return False, None

def detect_typosquatting(domain):
    """Détecte si le domaine imite une marque connue"""
    marques = ['apple', 'paypal', 'amazon', 'microsoft', 'google', 'facebook', 'netflix', 'dhl', 'fedex', 'ebay','dropbox','zoom']
    domain_lower = domain.lower().replace('-', '').replace('.', '')
    for marque in marques:
        if marque in domain_lower:
            # Vérifie que ce n'est PAS le domaine officiel
            if domain not in ['gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com'] and not domain.endswith(f"{marque}.com"):
                return True, f"Imite {marque}"
    return False, None

def detect_parking_provider(mx_list):
    """Détecte les hébergeurs de parking (domaines inactifs)"""
    parking_providers = ['above.com', 'parking', 'sedo', 'dan.com', 'bodis', 'domainpark', 'parkingcrew']
    mx_string = " ".join([mx["serveur"] for mx in mx_list]).lower()
    for provider in parking_providers:
        if provider in mx_string:
            return True, f"MX chez {provider} (parking)"
    return False, None

def analyze_mx_quality(mx_list):
    """Analyse la qualité des serveurs MX"""
    if not mx_list:
        return "Aucun serveur MX", -40
    
    issues = []
    penalty = 0
    
    # Nombre de serveurs MX (redondance)
    if len(mx_list) == 1:
        issues.append("Un seul serveur MX (pas de redondance)")
        penalty -= 0
    elif len(mx_list) == 2:
        issues.append("Redondance limitée (2 MX)")
        penalty -= 10
    elif len(mx_list) >= 3:
        pass  # Bonne redondance
    
    # Vérifier les priorités
    priorities = []
    for mx in mx_list:
        try:
            priorities.append(int(mx.get("priorite", 999)))
        except:
            priorities.append(999)
    
    if len(set(priorities)) == 1 and len(mx_list) > 1:
        issues.append("Tous les MX ont la même priorité")
        penalty -= 5
    
    # Détection hébergeurs suspects
    mx_string = " ".join([mx["serveur"] for mx in mx_list]).lower()
    if any(x in mx_string for x in ['above.com', 'parking', 'sedo', 'dan.com']):
        issues.append("Hébergeur de parking détecté")
        penalty -= 20
    
    if issues:
        return ", ".join(issues[:2]), penalty
    return "MX OK", penalty

def analyze_spf_advanced(spf_record, domain):
    """Analyse SPF avec détection d'anomalies et pénalités"""
    if not spf_record:
        return "SPF absent", -25
    
    spf_lower = spf_record.lower()
    penalty = 0
    issues = []
    
    #Compter les includes (limite RFC = 10)
    include_count = spf_lower.count('include:')
    if include_count > 10:
        issues.append(f"Trop d'includes ({include_count})")
        penalty -= 15
    elif include_count > 5:
        issues.append(f"Beaucoup d'includes ({include_count})")
        penalty -= 5
    
    #Vérifier les mécanismes (MX, A, etc.)
    if 'mx' in spf_lower and not any(x in spf_lower for x in ['include', 'redirect']):
        issues.append("SPF basé sur MX (peut être lent)")
        penalty -= 5
    
    #Détection SPF suspects
    if "ip6:" in spf_lower and "/48" in spf_lower:
        issues.append("SPF suspect (IPv6 auto-généré)")
        penalty -= 15
    
    #Qualité de la politique
    if "-all" in spf_lower:
        policy = "strict"
    elif "~all" in spf_lower:
        policy = "tolérant"
        penalty -= 2
    elif "?all" in spf_lower:
        policy = "neutre"
        penalty -= 10
    else:
        policy = "aucune"
        penalty -= 15
    
    #Cas spéciaux providers
    if "_spf.google.com" in spf_lower or "_spf.microsoft.com" in spf_lower:
        if include_count <= 3:
            return f"SPF {policy} (provider majeur)", max(penalty, 0)
    
    #Vérifier la taille (max 255 caractères)
    if len(spf_record) > 450:
        issues.append("SPF très long (>450)")
        penalty -= 10
    elif len(spf_record) > 255:
        issues.append("SPF long (>255)")
        penalty -= 5
    
    #Construction du message
    if issues:
        status = f"SPF {policy} - " + ", ".join(issues[:2])
        if len(issues) > 2:
            status += "..."
    else:
        status = f"SPF {policy}"
    
    return status, penalty

def analyze_dmarc(dmarc_record):
    """Analyse l'enregistrement DMARC"""
    if not dmarc_record:
        return "DMARC absent", -25
    
    dmarc_lower = dmarc_record.lower()
    penalty = 0
    issues = []
    
    # Politique principale
    if "p=reject" in dmarc_lower:
        policy = "strict"
    elif "p=quarantine" in dmarc_lower:
        policy = "modéré"
    elif "p=none" in dmarc_lower:
        policy = "surveillance"
        penalty -= 5
    else:
        policy = "invalide"
        penalty -= 15
    
    # Vérifier les sous-domaines (sp=)
    if "sp=none" in dmarc_lower:
        issues.append("sous-domaines non protégés")
        penalty -= 15
    elif "sp=quarantine" in dmarc_lower:
        issues.append("sous-domaines modérés")
        penalty -= 2
    elif "sp=reject" in dmarc_lower:
        pass  # Parfait
    
    # Pourcentage (pct=)
    if "pct=" in dmarc_lower:
        import re
        match = re.search(r'pct=(\d+)', dmarc_lower)
        if match and int(match.group(1)) < 100:
            issues.append(f"protection partielle ({match.group(1)}%)")
            penalty -= 5
    
    # Rapports (bonne pratique)
    if "rua=" not in dmarc_lower:
        issues.append("pas de rapports")
        penalty -= 3
    
    if issues:
        return f"DMARC {policy} - " + ", ".join(issues[:2]), penalty
    return f"DMARC {policy}", penalty

DISPOSABLE_DOMAINS = {
    "yopmail.com", "mailinator.com", "guerrillamail.com",
    "tempmail.com", "throwam.com", "sharklasers.com",
    "trashmail.com", "maildrop.cc", "dispostable.com",
    "fakeinbox.com", "spamgourmet.com", "mytemp.email"
}

def check_mail_reputation(email):
    
    if "@" not in email:
        return {"error": "Email invalide"}
    domain = email.split("@")[-1]
    result = {
        "email": email,
        "domaine": domain,
        "mx": [],
        "spf": None,
        "dmarc": None,
        "fournisseur": None,
        "alertes": [],
        "score": 100
    }

    # -------------------- MX --------------------
    try:
        url = f"https://api.mxtoolbox.com/api/v1/Lookup/MX/?argument={domain}&authorization={MXTOOLBOX_API_KEY}"
        resp = requests.get(url, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            seen = set()
            for item in data.get("Information", []):
                if isinstance(item, dict) and item.get("Hostname"):
                    host = item["Hostname"]
                    if host not in seen:
                        seen.add(host)
                        result["mx"].append({
                            "serveur": host,
                            "priorite": item.get("Pref", "N/A")
                        })
            if result["mx"]:
             mx_status, mx_penalty = analyze_mx_quality(result["mx"])
             if mx_penalty < 0:
                 result["alertes"].append(mx_status)
                 result["score"] += mx_penalty
            else:
             result["alertes"].append("Aucun serveur MX")
             result["score"] -= 40
        else:
            result["alertes"].append("Erreur MX")
            result["score"] -= 20
    except:
        result["alertes"].append("Timeout MX")
        result["score"] -= 20
    
    result["fournisseur"] = detect_provider(result["mx"])
    
    # -------------------- SPF --------------------
    try:
        url = f"https://api.mxtoolbox.com/api/v1/Lookup/SPF/?argument={domain}&authorization={MXTOOLBOX_API_KEY}"
        resp = requests.get(url, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("Records"):
                spf_record = data["Records"][0]
                result["spf"] = spf_record
                status, penalty = analyze_spf_advanced(spf_record, domain)
                if penalty < 0:
                    result["alertes"].append(status)
                    result["score"] += penalty
                elif status == "SPF strict" or status == "SPF valide (provider majeur)":
                    pass  # Pas d'alerte pour les bonnes configs
            else:
                result["alertes"].append("SPF absent")
                result["score"] -= 25
        else:
            result["alertes"].append("Erreur SPF")
            result["score"] -= 15
    except:
        result["alertes"].append("Timeout SPF")
        result["score"] -= 15
    
    # -------------------- DMARC --------------------
    try:
        url = f"https://api.mxtoolbox.com/api/v1/Lookup/DMARC/?argument={domain}&authorization={MXTOOLBOX_API_KEY}"
        resp = requests.get(url, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("Records"):
                dmarc_record = data["Records"][0]
                result["dmarc"] = dmarc_record
                status, penalty = analyze_dmarc(dmarc_record)
                if penalty < 0:
                    result["alertes"].append(status)
                    result["score"] += penalty
            else:
                result["alertes"].append("DMARC absent")
                result["score"] -= 25
        else:
            result["alertes"].append("Erreur DMARC")
            result["score"] -= 15
    except:
        result["alertes"].append("Timeout DMARC")
        result["score"] -= 15
    
    # -------------------- Détection phishing  --------------------
    
    #Vérifier le TLD
    is_suspicious, tld_alert = detect_suspicious_tld(domain)
    if is_suspicious:
        result["alertes"].append(tld_alert)
        result["score"] -= 20
    
    #Vérifier le typosquatting
    is_typo, typo_alert = detect_typosquatting(domain)
    if is_typo:
        result["alertes"].append(typo_alert)
        result["score"] -= 30
    
    #Vérifier l'hébergement de parking
    if result["mx"]:
        is_parking, parking_alert = detect_parking_provider(result["mx"])
        if is_parking:
            result["alertes"].append(parking_alert)
            result["score"] -= 15
    
    if domain in ["gmail.com", "outlook.com", "hotmail.com", "yahoo.com","microsoft.com","google.com","dropbox.com", "zoom.us", "icloud.com", "protonmail.com","proton.me", "zoho.com", "mail.ru", "aol.com","twitter.com", "github.com", "microsoft.com", "amazon.com", "linkedin.com", "apple.com", "paypal.com", "facebook.com", "netflix.com", "action.eff.org", "python.org", "stackoverflow.com", "cloudflare.com", "discord.com", "slack.com", "adobe.com", "spotify.com", "mozilla.org"]:
     result["score"] = 100
     result["verdict"] = "fiable"
     result["alertes"] = [a for a in result["alertes"] if "DMARC" not in a and "SPF" not in a]

    # -------------------- Nettoyage et verdict --------------------
    result["alertes"] = list(dict.fromkeys(result["alertes"]))
    result["score"] = max(0, min(100, result["score"]))
    
    if result["score"] >= 80:
        result["verdict"] = "fiable"
    elif result["score"] >= 50:
        result["verdict"] = "douteux"
    else:
        result["verdict"] = "suspect"
    
    return result
