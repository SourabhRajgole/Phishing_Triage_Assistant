import argparse
import json
from pathlib import Path

from .parser import parse_eml
from .indicators import compute_indicators
from .scoring import score_email
from .report import render_markdown, render_pdf


def main() -> int:
    p = argparse.ArgumentParser(prog="phish-triage", description="Phishing Email Triage Assistant")
    p.add_argument("--eml", required=True, help="Path to .eml file")
    p.add_argument("--out-md", default=None, help="Write Markdown report to this path (optional)")
    p.add_argument("--out-pdf", default=None, help="Write PDF report to this path (optional)")
    p.add_argument("--out-json", default=None, help="Write JSON analysis to this path (optional)")
    args = p.parse_args()

    parsed = parse_eml(Path(args.eml))
    indicators = compute_indicators(parsed)
    score = score_email(parsed, indicators)

    # Console summary
    print("Subject:", parsed.get("subject") or "(none)")
    print("From:", parsed.get("from_raw") or "(none)")
    print("Reply-To:", parsed.get("reply_to_raw") or "(none)")
    print("To:", parsed.get("to_raw") or "(none)")
    print("Attachments:", len(parsed.get("attachments", [])))
    print("URLs:", len(parsed.get("urls", [])))
    print(f"Risk: {score['risk']}  Score: {score['total']}/100")

    # Optional outputs
    if args.out_md:
        md = render_markdown(parsed, indicators, score)
        Path(args.out_md).write_text(md, encoding="utf-8")

    if args.out_pdf:
        render_pdf(Path(args.out_pdf), parsed, indicators, score)

    if args.out_json:
        result = {
            "eml_path": str(args.eml),
            "parsed": parsed,
            "indicators": indicators,
            "score": score,
        }
        Path(args.out_json).write_text(json.dumps(result, indent=2), encoding="utf-8")

    return 0
