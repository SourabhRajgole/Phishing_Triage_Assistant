import argparse
from pathlib import Path

from .parser import parse_eml
from .indicators import compute_indicators   


def main() -> int:
    p = argparse.ArgumentParser(prog="phish-triage")
    p.add_argument("--eml", required=True, help="Path to .eml file")
    args = p.parse_args()

    parsed = parse_eml(Path(args.eml))      

    ind = compute_indicators(parsed)     

    print("From domain:", ind["from_domain"])
    print("Reply-To domain:", ind["reply_to_domain"])
    print("From/Reply-To mismatch:", ind["from_reply_to_mismatch"])

    auth = ind["auth"]
    print("SPF:", auth.get("spf") or "(not found)")
    print("DKIM:", auth.get("dkim") or "(not found)")
    print("DMARC:", auth.get("dmarc") or "(not found)")

    print("URL details:")
    for u in ind["url_details"][:5]:
        flags = []
        if u["punycode"]:
            flags.append("punycode")
        if u["risky_tld"]:
            flags.append("risky-tld")
        flag_str = f" ({', '.join(flags)})" if flags else ""
        print(" -", u["domain_display"], flag_str)

    return 0
