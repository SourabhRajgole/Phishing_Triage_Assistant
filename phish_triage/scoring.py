def _risk_label(score: int) -> str:
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def score_email(parsed: dict, indicators: dict) -> dict:
    """
    Explainable heuristic scoring (0-100).
    """
    total = 0
    breakdown = []

    # From / Reply-To mismatch
    if indicators.get("from_reply_to_mismatch"):
        total += 25
        breakdown.append({"points": 25, "reason": "From and Reply-To domains do not match."})

    # SPF/DKIM/DMARC (best-effort)
    auth = indicators.get("auth", {}) or {}
    spf = (auth.get("spf") or "").lower()
    dkim = (auth.get("dkim") or "").lower()
    dmarc = (auth.get("dmarc") or "").lower()

    if spf in {"fail", "softfail", "permerror"}:
        total += 20
        breakdown.append({"points": 20, "reason": f"SPF result is {spf}."})

    if dkim in {"fail", "permerror"}:
        total += 20
        breakdown.append({"points": 20, "reason": f"DKIM result is {dkim}."})

    if dmarc == "fail":
        total += 20
        breakdown.append({"points": 20, "reason": "DMARC result is fail."})

    # URL-based signals
    urls = indicators.get("url_details", []) or []
    if urls:
        total += 5
        breakdown.append({"points": 5, "reason": f"Email contains {len(urls)} URL(s)."})

    risky = sum(1 for u in urls if u.get("risky_tld"))
    if risky:
        add = min(15, risky * 5)
        total += add
        breakdown.append({"points": add, "reason": f"{risky} URL(s) use a risky TLD."})

    puny = sum(1 for u in urls if u.get("punycode"))
    if puny:
        add = min(15, puny * 8)
        total += add
        breakdown.append({"points": add, "reason": f"{puny} URL domain(s) appear punycode-encoded (possible lookalike)."})


    # Attachments
    atts = indicators.get("attachments", []) or []
    if atts:
        total += 10
        breakdown.append({"points": 10, "reason": f"Email contains {len(atts)} attachment(s)."})

        # high-risk extensions
        bad_ext = {".exe", ".js", ".vbs", ".scr", ".bat", ".cmd", ".lnk", ".iso", ".img", ".hta"}
        for a in atts:
            fn = (a.get("filename") or "").lower()
            for ext in bad_ext:
                if fn.endswith(ext):
                    total += 20
                    breakdown.append({"points": 20, "reason": f"Attachment '{fn}' has high-risk extension {ext}."})
                    break

    total = max(0, min(100, total))
    return {"total": total, "risk": _risk_label(total), "breakdown": breakdown}
