import textwrap

def print_ioc_report(data: dict, show_evidence: bool = False):
    indicator   = data.get("indicator", "N/A")
    ioc_type    = data.get("type", "N/A").upper()
    ti_data     = data.get("ti_data", {})
    rag_context = data.get("rag_context", [])
    llm         = data.get("llm_analysis", {})

    def line():
        print("=" * 72)

    def section(title):
        print("-" * 72)
        print(f"  {title}")
        print("-" * 72)

    def wrap(text, indent="    ", width=66):
        if not text:
            return
        for part in textwrap.wrap(str(text), width=width):
            print(f"{indent}{part}")

    def field(label, value):
        print(f"  {label:<20}: {value if value not in (None, '', [], {}) else 'N/A'}")

    line()
    print("  IOC ANALYSIS REPORT")
    line()
    field("Indicator",   indicator)
    field("Type",        ioc_type)
    field("Classification", data.get("ioc_classification", "N/A"))
    print()

    # ── Threat Intelligence ──────────────────────────────
    section("THREAT INTELLIGENCE")
    if ioc_type == "HASH":
        vt = ti_data.get("vt_detection") or {}
        field("File Type",       ti_data.get("file_type"))
        field("First Submission",ti_data.get("first_submission"))
        field("VT Malicious",    vt.get("malicious", "N/A"))
        field("VT Suspicious",   vt.get("suspicious", "N/A"))
        field("Reputation",      ti_data.get("reputation"))
        field("Final Verdict",   ti_data.get("final_verdict"))

    elif ioc_type == "IP":
        field("VT Verdict",      ti_data.get("vt_verdict"))
        field("VT Stats",        ti_data.get("vt_stats"))
        field("AbuseIPDB",       ti_data.get("abuseipdb", {}).get("abuse_score") if ti_data.get("abuseipdb") else "N/A")
        field("Country",         ti_data.get("country"))
        field("Final Verdict",   ti_data.get("final_verdict"))

    elif ioc_type == "DOMAIN":
        field("VT Verdict",      ti_data.get("vt_verdict"))
        field("VT Detection",    ti_data.get("vt_detection"))
        field("Risk Score",      ti_data.get("global_risk_score"))
        field("Registrar",       ti_data.get("registrar"))
        field("Final Verdict",   ti_data.get("final_verdict"))

    elif ioc_type == "URL":
        field("VT Verdict",      ti_data.get("virustotal", {}).get("verdict") if ti_data.get("virustotal") else "N/A")
        field("GSB Verdict",     ti_data.get("google_safe_browsing", {}).get("verdict") if ti_data.get("google_safe_browsing") else "N/A")
        field("PhishTank",       ti_data.get("phishtank", {}).get("verdict") if ti_data.get("phishtank") else "N/A")
        field("Risk Score",      ti_data.get("global_risk_score"))
        field("Final Verdict",   ti_data.get("final_verdict"))

    elif ioc_type == "MAIL":
        field("Domain",          ti_data.get("domain"))
        field("SPF",             ti_data.get("spf"))
        field("DMARC",           ti_data.get("dmarc"))
        field("MX Score",        ti_data.get("score"))
        field("Provider",        ti_data.get("fournisseur"))
        field("Final Verdict",   ti_data.get("final_verdict"))
        alerts = ti_data.get("alertes", [])
        if alerts:
            print(f"  {'Alerts':<20}:")
            for a in alerts[:3]:
                print(f"    - {a}")
    print()

    # ── RAG Evidence ────────────────────────────────────
    if show_evidence:
        section("RAG EVIDENCE")
        if rag_context:
            for i, ctx in enumerate(rag_context, 1):
                print(f"  [{i}] {ctx.get('source','N/A')} | score={ctx.get('score','N/A')}")
                wrap(ctx.get("text", ""))
                print()
        else:
            print("  No RAG evidence retrieved.\n")

    # ── LLM Analysis ────────────────────────────────────
    section("LLM ANALYSIS")
    field("Model",           llm.get("model", "N/A"))
    field("Threat Level",    llm.get("threat_level", "N/A").upper())
    field("Score",           llm.get("score", "N/A"))
    field("RAG Used",        "YES" if llm.get("rag_used") else "NO")
    field("Fallback",        "YES" if llm.get("fallback") else "NO")
    print()
    print("  Summary:")
    wrap(llm.get("summary", "N/A"))
    print()
    print("  Recommendation:")
    wrap(llm.get("recommended_action") or llm.get("recommandation", "N/A"))
    print()
    tags = llm.get("tags", [])
    field("Tags", ", ".join(tags) if tags else "none")
    print()
    line()
    print()