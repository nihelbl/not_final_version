# services/rag_gate.py
"""Décision RAG (skip vs retrieval) et requête dynamique à partir des signaux TI — tous types d'IOC."""

from __future__ import annotations


def _lower(s: object) -> str:
    return (str(s) if s is not None else "").strip().lower()


def _as_int(x: object, default: int = 0) -> int:
    try:
        if x is None:
            return default
        return int(x)
    except (TypeError, ValueError):
        return default


def _as_float(x: object, default: float = 0.0) -> float:
    try:
        if x is None:
            return default
        return float(x)
    except (TypeError, ValueError):
        return default


def _mail_auth_state(value: object) -> str:
    s = _lower(value)
    if s in ("", "unknown", "n/a", "na", "none", "null", "absent", "missing", "false"):
        return "missing"
    if "permerror" in s or "softfail" in s or "neutral" in s or "permissive" in s:
        return "permissive"
    if "valid" in s or "pass" in s or "enforce" in s or "quarantine" in s or "reject" in s:
        return "valid"
    return "present"


def collect_ti_signals(ioc_type: str, raw: dict) -> dict:
    """Extrait des signaux comparables depuis les payloads bruts des services."""
    t = _lower(ioc_type)
    out: dict = {"ioc_type": t}
    if not isinstance(raw, dict):
        return out

    if t == "domain":
        vt = raw.get("virustotal") or {}
        det = vt.get("detection") or {}
        out.update(
            {
                "verdict": _lower(raw.get("global_risk_level") or raw.get("final_verdict")),
                "global_risk_score": _as_int(raw.get("global_risk_score"), 999),
                "vt_malicious": _as_int(det.get("malicious")),
                "vt_suspicious": _as_int(det.get("suspicious")),
                "vt_reputation": _as_int(vt.get("reputation_score")),
            }
        )

    elif t == "ip":
        vt = raw.get("virustotal") or {}
        stats = vt.get("stats") or {}
        abuse = raw.get("abuseipdb") or {}
        otx = raw.get("otx") or {}
        out.update(
            {
                "verdict": _lower(raw.get("final_verdict")),
                "vt_malicious": _as_int(stats.get("malicious")),
                "vt_suspicious": _as_int(stats.get("suspicious")),
                "abuse_score": _as_int(abuse.get("abuse_score")),
                "otx_pulses": _as_int(otx.get("pulse_count")),
            }
        )

    elif t == "hash":
        det = raw.get("detection") or {}
        otx = raw.get("otx") or {}
        out.update(
            {
                "verdict": _lower(raw.get("risk_level") or raw.get("final_verdict")),
                "vt_malicious": _as_int(det.get("malicious")),
                "vt_suspicious": _as_int(det.get("suspicious")),
                "vt_reputation": _as_int(raw.get("reputation_score")),
                "otx_pulses": _as_int(otx.get("pulse_count")),
            }
        )

    elif t == "url":
        vendors = raw.get("vendors") or {}
        vt = vendors.get("virustotal") or {}
        gsb = vendors.get("google_safe_browsing") or {}
        pt = vendors.get("phishtank") or {}
        out.update(
            {
                "verdict": _lower(raw.get("final_verdict") or raw.get("global_risk_level")),
                "global_risk_score": _as_int(raw.get("global_risk_score"), 999),
                "vt_malicious": _as_int(vt.get("malicious")),
                "vt_suspicious": _as_int(vt.get("suspicious")),
                "gsb_verdict": _lower(gsb.get("verdict")),
                "phishtank_verdict": _lower(pt.get("verdict")),
            }
        )

    elif t == "mail":
        alertes = raw.get("alertes") or []
        n_alerts = len(alertes) if isinstance(alertes, list) else 0
        spf_state = _mail_auth_state(raw.get("spf"))
        dmarc_state = _mail_auth_state(raw.get("dmarc"))
        dkim_state = _mail_auth_state(raw.get("dkim"))
        out.update(
            {
                "verdict": _lower(raw.get("verdict")),
                "mailbox_score": _as_int(raw.get("score"), 0),
                "alert_count": n_alerts,
                "spf_state": spf_state,
                "dmarc_state": dmarc_state,
                "dkim_state": dkim_state,
            }
        )

    elif t == "cve":
        risk = raw.get("risk") or {}
        out.update(
            {
                "verdict": _lower(risk.get("level") or raw.get("severity")),
                "cvss": _as_float(raw.get("cvss_score")),
            }
        )

    return out


def build_rag_query(ioc_type: str, raw: dict, ti_data: dict) -> str:
    """
    Requête dense factuelle pour le retrieval (évite le biais de
    « domain malicious reputation threat » qui attire les chunks négatifs génériques).
    """
    sig = collect_ti_signals(ioc_type, raw)
    t = sig.get("ioc_type") or _lower(ioc_type)
    parts = [
        t,
        "security analyst triage",
        "correlate telemetry",
        "false positive assessment",
    ]

    if t == "domain":
        parts.append(
            f"vt_malicious={sig.get('vt_malicious', 0)} vt_suspicious={sig.get('vt_suspicious', 0)} "
            f"vt_reputation={sig.get('vt_reputation')} global_risk_score={sig.get('global_risk_score')} "
            f"verdict={sig.get('verdict', 'unknown')}"
        )
        cd = ti_data.get("creation_date")
        if cd and cd != "unknown":
            parts.append(f"registration_context={cd}")

    elif t == "ip":
        parts.append(
            f"vt_malicious={sig.get('vt_malicious', 0)} vt_suspicious={sig.get('vt_suspicious', 0)} "
            f"abuseipdb_score={sig.get('abuse_score', 0)} otx_pulse_count={sig.get('otx_pulses', 0)} "
            f"verdict={sig.get('verdict', 'unknown')}"
        )

    elif t == "hash":
        parts.append(
            f"vt_malicious={sig.get('vt_malicious', 0)} vt_suspicious={sig.get('vt_suspicious', 0)} "
            f"vt_reputation={sig.get('vt_reputation')} otx_pulse_count={sig.get('otx_pulses', 0)} "
            f"verdict={sig.get('verdict', 'unknown')}"
        )
        ft = ti_data.get("file_type")
        if ft and ft != "unknown":
            parts.append(f"file_type={ft}")

    elif t == "url":
        parts.append(
            f"vt_malicious={sig.get('vt_malicious', 0)} vt_suspicious={sig.get('vt_suspicious', 0)} "
            f"gsb={sig.get('gsb_verdict', 'n/a')} phishtank={sig.get('phishtank_verdict', 'n/a')} "
            f"global_risk_score={sig.get('global_risk_score')} verdict={sig.get('verdict', 'unknown')}"
        )

    elif t == "mail":
        parts.append(
            f"mailbox_score={sig.get('mailbox_score', 0)} alerts={sig.get('alert_count', 0)} "
            f"verdict={sig.get('verdict', 'unknown')}"
        )

    elif t == "cve":
        parts.append(
            f"cvss={sig.get('cvss')} severity={sig.get('verdict', 'unknown')} "
            "patching prioritization vulnerability management"
        )

    return " ".join(str(p) for p in parts if p)
