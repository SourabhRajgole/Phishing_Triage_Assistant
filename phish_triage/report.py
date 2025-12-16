from datetime import datetime
from pathlib import Path
from typing import List

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


def render_markdown(parsed: dict, indicators: dict, score: dict) -> str:
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
    lines: List[str] = []

    lines.append("# Phishing Triage Report\n")
    lines.append(f"- **Generated (UTC):** {now}")
    lines.append(f"- **Risk:** **{score['risk']}**")
    lines.append(f"- **Score:** **{score['total']}/100**\n")

    lines.append("## Email Summary")
    lines.append(f"- **Subject:** {parsed.get('subject') or '(none)'}")
    lines.append(f"- **From:** {parsed.get('from_raw') or '(none)'}")
    lines.append(f"- **Reply-To:** {parsed.get('reply_to_raw') or '(none)'}")
    lines.append(f"- **To:** {parsed.get('to_raw') or '(none)'}")
    lines.append(f"- **Date:** {parsed.get('date') or '(none)'}")
    lines.append(f"- **Message-ID:** {parsed.get('message_id') or '(none)'}\n")

    lines.append("## Key Findings")
    if score.get("breakdown"):
        for b in score["breakdown"]:
            lines.append(f"- (+{b['points']}) {b['reason']}")
    else:
        lines.append("- No significant indicators triggered in the current heuristic set.")
    lines.append("")

    auth = indicators.get("auth", {}) or {}
    lines.append("## Authentication Signals (Best-Effort)")
    lines.append(f"- **SPF:** {auth.get('spf') or '(not found)'}")
    lines.append(f"- **DKIM:** {auth.get('dkim') or '(not found)'}")
    lines.append(f"- **DMARC:** {auth.get('dmarc') or '(not found)'}")
    lines.append("")

    lines.append("## URLs")
    url_details = indicators.get("url_details", []) or []
    if not url_details:
        lines.append("- None found.\n")
    else:
        for u in url_details:
            flags = []
            if u.get("punycode"):
                flags.append("punycode/lookalike")
            if u.get("risky_tld"):
                flags.append("risky TLD")
            if u.get("domain_age_days") is None:
                flags.append("domain age: (placeholder)")
            flag_str = f" — _{', '.join(flags)}_" if flags else ""
            lines.append(f"- {u['url']}{flag_str} (domain: `{u.get('domain_display')}`)")
        lines.append("")

    lines.append("## Attachments")
    atts = indicators.get("attachments", []) or []
    if not atts:
        lines.append("- None.\n")
    else:
        for a in atts:
            lines.append(f"- `{a.get('filename')}` ({a.get('content_type')}), {a.get('size_bytes')} bytes")
        lines.append("")

    lines.append("## Header Checks")
    lines.append(f"- **From domain:** `{indicators.get('from_domain') or '(none)'}`")
    lines.append(f"- **Reply-To domain:** `{indicators.get('reply_to_domain') or '(none)'}`")
    lines.append(f"- **From/Reply-To mismatch:** `{indicators.get('from_reply_to_mismatch')}`\n")

    preview = (parsed.get("body_text") or "").strip()
    if not preview:
        preview = "(no text body extracted)"
    preview = preview[:500]

    lines.append("## Body Preview (first 500 chars)")
    lines.append("```")
    lines.append(preview)
    lines.append("```")

    return "\n".join(lines)


def render_pdf(out_path: Path, parsed: dict, indicators: dict, score: dict) -> None:
    """
    One-page friendly PDF: truncates long lists.
    """
    c = canvas.Canvas(str(out_path), pagesize=letter)
    width, height = letter

    y = height - 50
    left = 50
    line_h = 14

    def draw(text: str, bold: bool = False):
        nonlocal y
        if y < 60:
            c.showPage()
            y = height - 50
        c.setFont("Helvetica-Bold" if bold else "Helvetica", 11 if bold else 10)
        c.drawString(left, y, text)
        y -= line_h

    draw("Phishing Triage Report", bold=True)
    draw(f"Risk: {score['risk']}   Score: {score['total']}/100", bold=True)
    draw("")

    draw("Email Summary", bold=True)
    draw(f"Subject: {parsed.get('subject') or '(none)'}")
    draw(f"From: {parsed.get('from_raw') or '(none)'}")
    draw(f"Reply-To: {parsed.get('reply_to_raw') or '(none)'}")
    draw(f"To: {parsed.get('to_raw') or '(none)'}")
    draw(f"Date: {parsed.get('date') or '(none)'}")
    draw("")

    draw("Key Findings (truncated)", bold=True)
    breakdown = score.get("breakdown") or []
    if not breakdown:
        draw("No significant indicators triggered in the current heuristic set.")
    else:
        for item in breakdown[:6]:
            draw(f"+{item['points']}: {item['reason']}")
        if len(breakdown) > 6:
            draw(f"... ({len(breakdown) - 6} more)")

    draw("")
    draw("URLs (truncated)", bold=True)
    url_details = indicators.get("url_details") or []
    if not url_details:
        draw("None found.")
    else:
        for u in url_details[:6]:
            flags = []
            if u.get("punycode"):
                flags.append("punycode")
            if u.get("risky_tld"):
                flags.append("risky-tld")
            flag_str = f" [{', '.join(flags)}]" if flags else ""
            draw(f"- {u.get('url')}{flag_str}")
        if len(url_details) > 6:
            draw(f"... ({len(url_details) - 6} more)")

    draw("")
    draw("Attachments (truncated)", bold=True)
    atts = indicators.get("attachments") or []
    if not atts:
        draw("None.")
    else:
        for a in atts[:6]:
            draw(f"- {a.get('filename')} ({a.get('content_type')}), {a.get('size_bytes')} bytes")
        if len(atts) > 6:
            draw(f"... ({len(atts) - 6} more)")

    c.save()
