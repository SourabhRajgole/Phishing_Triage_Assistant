from email import policy
from email.parser import BytesParser
from email.message import Message
from pathlib import Path
from typing import Dict, List, Tuple
import re
from html.parser import HTMLParser



_URL_RE = re.compile(r"(?i)\b(https?://[^\s<>'\"]+|www\.[^\s<>'\"]+)")

class _HrefParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        for k, v in attrs:
            if (k or "").lower() == "href" and v:
                self.hrefs.append(v)

def _extract_urls_from_text(text: str) -> list[str]:
    if not text:
        return []
    urls = []
    for m in _URL_RE.finditer(text):
        u = m.group(1).strip().strip(").,;!\"'<>")
        if u.lower().startswith("www."):
            u = "http://" + u
        urls.append(u)
    return urls

def _extract_urls_from_html(html: str) -> list[str]:
    if not html:
        return []
    urls = []

    p = _HrefParser()
    try:
        p.feed(html)
        for h in p.hrefs:
            urls.extend(_extract_urls_from_text(h))
    except Exception:
        pass

    urls.extend(_extract_urls_from_text(html))
    return urls

def _get_header(msg: Message, name: str) -> str:
    v = msg.get(name)
    return str(v).strip() if v else ""


def _collect_headers(msg: Message) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in msg.items():
        if k in out:
            out[k] = out[k] + "\n" + str(v)
        else:
            out[k] = str(v)
    return out


def _extract_parts(msg: Message) -> Tuple[str, str, List[Dict]]:
    """
    Returns (text_body, html_body, attachments_metadata)
    attachments_metadata items: {filename, content_type, size_bytes}
    """
    text_chunks: List[str] = []
    html_chunks: List[str] = []
    attachments: List[Dict] = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype.startswith("multipart/"):
                continue

            filename = part.get_filename()
            disp = part.get_content_disposition()  # attachment/inline/None

            if filename or disp == "attachment":
                payload = part.get_payload(decode=True) or b""
                attachments.append({
                    "filename": filename or "(no-filename)",
                    "content_type": ctype,
                    "size_bytes": len(payload),
                })
                continue

            try:
                content = part.get_content()
            except Exception:
                payload = part.get_payload(decode=True) or b""
                content = payload.decode(errors="replace")

            if ctype == "text/plain":
                text_chunks.append(content)
            elif ctype == "text/html":
                html_chunks.append(content)
    else:
        ctype = msg.get_content_type()
        try:
            content = msg.get_content()
        except Exception:
            payload = msg.get_payload(decode=True) or b""
            content = payload.decode(errors="replace")

        if ctype == "text/plain":
            text_chunks.append(content)
        elif ctype == "text/html":
            html_chunks.append(content)

    return ("\n\n".join(t.strip() for t in text_chunks if t and t.strip()),
            "\n\n".join(h.strip() for h in html_chunks if h and h.strip()),
            attachments)


def parse_eml(eml_path: Path) -> Dict:
    """
    Minimal parsed structure for the MVP.
    """
    raw = eml_path.read_bytes()
    msg = BytesParser(policy=policy.default).parsebytes(raw)

    body_text, body_html, attachments = _extract_parts(msg)

    return {
        "subject": _get_header(msg, "Subject"),
        "date": _get_header(msg, "Date"),
        "message_id": _get_header(msg, "Message-ID"),
        "from_raw": _get_header(msg, "From"),
        "reply_to_raw": _get_header(msg, "Reply-To"),
        "return_path": _get_header(msg, "Return-Path"),
        "to_raw": _get_header(msg, "To"),
        "cc_raw": _get_header(msg, "Cc"),
        "authentication_results": _get_header(msg, "Authentication-Results"),
        "received_spf": _get_header(msg, "Received-SPF"),
        "headers": _collect_headers(msg),
        "body_text": body_text,
        "body_html": body_html,
        "attachments": attachments,
        "urls": sorted(set(_extract_urls_from_text(body_text) + _extract_urls_from_html(body_html))),

    }
