import re
from email.utils import parseaddr
from urllib.parse import urlparse

RISKY_TLDS = {"zip", "mov", "xyz", "top", "click", "gq", "tk", "icu", "work"}


def _email_domain(raw: str) -> str:
    _, addr = parseaddr(raw or "")
    if "@" in addr:
        return addr.split("@", 1)[1].lower().strip(" >")
    return ""


def _domain_from_url(u: str) -> str:
    try:
        return (urlparse(u).hostname or "").lower()
    except Exception:
        return ""


def _tld(domain: str) -> str:
    parts = (domain or "").split(".")
    return parts[-1].lower() if len(parts) >= 2 else ""


def _is_punycode(domain: str) -> bool:
    return any(lbl.startswith("xn--") for lbl in (domain or "").split("."))


def _decode_idna(domain: str) -> str:
    try:
        return domain.encode("ascii", errors="ignore").decode("idna")
    except Exception:
        return domain


def _extract_auth(authentication_results: str, received_spf: str) -> dict:
    blob = (" ".join([authentication_results or "", received_spf or ""])).strip().lower()

    def pick(pat: str) -> str:
        m = re.search(pat, blob)
        return m.group(1) if m else ""

    return {
        "spf": pick(r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b"),
        "dkim": pick(r"\bdkim=(pass|fail|neutral|none|temperror|permerror)\b"),
        "dmarc": pick(r"\bdmarc=(pass|fail|bestguesspass|none)\b"),
        "raw": (authentication_results or "") + ("\n" + received_spf if received_spf else ""),
    }


def compute_indicators(parsed: dict) -> dict:
    from_dom = _email_domain(parsed.get("from_raw", ""))
    reply_dom = _email_domain(parsed.get("reply_to_raw", ""))

    mismatch = bool(from_dom) and bool(reply_dom) and (from_dom != reply_dom)
    auth = _extract_auth(parsed.get("authentication_results", ""), parsed.get("received_spf", ""))

    url_details = []
    for u in parsed.get("urls", []) or []:
        d = _domain_from_url(u)
        td = _tld(d)
        puny = _is_punycode(d)
        url_details.append({
            "url": u,
            "domain": d,
            "domain_display": _decode_idna(d) if puny else d,
            "tld": td,
            "punycode": puny,
            "risky_tld": (td in RISKY_TLDS) if td else False,
            "domain_age_days": None,  # placeholder for later enrichment
        })

    return {
        "from_domain": from_dom,
        "reply_to_domain": reply_dom,
        "from_reply_to_mismatch": mismatch,
        "auth": auth,
        "url_details": url_details,
        "attachments": parsed.get("attachments", []),
    }
