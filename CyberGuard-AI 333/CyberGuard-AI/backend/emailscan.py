"""
CyberGuard AI — emailscan.py
Email analysis: spoofing detection (From vs Reply-To/Return-Path mismatch),
phishing keyword detection, link extraction, and attachment detection.

Named `emailscan.py` (not `email.py`) so it never shadows Python's stdlib
`email` package, which this module uses internally to parse .eml files.
"""

import re
import email
from email import policy
from email.parser import BytesParser, Parser

PHISHING_KEYWORDS = [
    "verify your account", "account suspended", "confirm your identity",
    "urgent action required", "click here immediately", "your account has been locked",
    "update your payment", "unusual activity", "security alert", "act now",
    "limited time", "claim your prize", "you have won", "password expires",
    "unauthorized login attempt", "verify now", "suspended", "reactivate",
]

URL_REGEX = re.compile(r"https?://[^\s\"'<>\)]+")

SUSPICIOUS_URL_KEYWORDS = ["login", "verify", "secure", "update", "account", "confirm", "bank"]


def _extract_domain(address: str) -> str:
    match = re.search(r"@([\w.-]+)", address or "")
    return match.group(1).lower() if match else ""


def _parse_source(raw_bytes: bytes = None, raw_text: str = None):
    """Parse raw .eml bytes or plain pasted email text into an EmailMessage."""
    if raw_bytes is not None:
        try:
            return BytesParser(policy=policy.default).parsebytes(raw_bytes)
        except Exception:
            raw_text = raw_bytes.decode("utf-8", errors="ignore")
    return Parser(policy=policy.default).parsestr(raw_text or "")


def analyze_email(raw_bytes: bytes = None, raw_text: str = None) -> dict:
    msg = _parse_source(raw_bytes, raw_text)

    from_addr = msg.get("From", "") or ""
    reply_to = msg.get("Reply-To", "") or ""
    return_path = msg.get("Return-Path", "") or ""
    subject = msg.get("Subject", "") or ""

    # ---- Body extraction ----
    body = ""
    try:
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body += part.get_content()
        else:
            body = msg.get_content()
    except Exception:
        # Fall back to raw text if structured parsing fails
        body = raw_text or (raw_bytes.decode("utf-8", errors="ignore") if raw_bytes else "")

    full_text = f"{subject}\n{body}".lower()

    # ---- Spoofing check ----
    from_domain = _extract_domain(from_addr)
    reply_domain = _extract_domain(reply_to)
    return_domain = _extract_domain(return_path)

    spoofing_detected = False
    spoofing_reason = "No mismatch detected"
    if reply_domain and from_domain and reply_domain != from_domain:
        spoofing_detected = True
        spoofing_reason = f"'From' domain ({from_domain}) differs from 'Reply-To' domain ({reply_domain})"
    elif return_domain and from_domain and return_domain != from_domain:
        spoofing_detected = True
        spoofing_reason = f"'From' domain ({from_domain}) differs from 'Return-Path' domain ({return_domain})"

    # ---- Phishing keyword check ----
    matched_keywords = [kw for kw in PHISHING_KEYWORDS if kw in full_text]

    # ---- Link extraction ----
    links = list(dict.fromkeys(URL_REGEX.findall(body or "")))  # dedupe, preserve order
    link_findings = []
    for link in links:
        is_suspicious = any(k in link.lower() for k in SUSPICIOUS_URL_KEYWORDS) or bool(
            re.search(r"bit\.ly|tinyurl|t\.co|goo\.gl", link.lower())
        )
        link_findings.append({"url": link, "suspicious": is_suspicious})

    # ---- Attachments ----
    attachments = []
    try:
        for part in msg.iter_attachments():
            attachments.append(part.get_filename() or "unnamed attachment")
    except Exception:
        pass
    dangerous_ext = re.compile(r"\.(exe|scr|bat|cmd|js|vbs|jar|apk)$", re.IGNORECASE)
    risky_attachments = [a for a in attachments if dangerous_ext.search(a or "")]

    # ---- Risk scoring ----
    risk_points = 0
    if spoofing_detected:
        risk_points += 35
    risk_points += min(len(matched_keywords) * 12, 36)
    suspicious_links = [l for l in link_findings if l["suspicious"]]
    risk_points += min(len(suspicious_links) * 15, 30)
    if risky_attachments:
        risk_points += 40

    if risk_points >= 55:
        risk_level = "high"
        verdict = "This email shows strong signs of phishing"
    elif risk_points >= 25:
        risk_level = "medium"
        verdict = "This email has some suspicious characteristics"
    else:
        risk_level = "low"
        verdict = "This email appears legitimate based on available checks"

    metrics = [
        {"label": "Sender Spoofing", "value": "Detected" if spoofing_detected else "Not detected",
         "status": "bad" if spoofing_detected else "ok"},
        {"label": "Phishing Keywords", "value": f"{len(matched_keywords)} found" if matched_keywords else "None found",
         "status": "bad" if matched_keywords else "ok"},
        {"label": "Suspicious Links", "value": f"{len(suspicious_links)} of {len(links)}",
         "status": "bad" if suspicious_links else ("warn" if links else "ok")},
        {"label": "Risky Attachments", "value": f"{len(risky_attachments)} found" if risky_attachments else "None found",
         "status": "bad" if risky_attachments else "ok"},
    ]

    explanation_parts = []
    if spoofing_detected:
        explanation_parts.append(spoofing_reason + ".")
    if matched_keywords:
        explanation_parts.append(
            f"The message contains {len(matched_keywords)} phrase(s) commonly used in phishing attempts, "
            f"such as \u201c{matched_keywords[0]}\u201d."
        )
    if suspicious_links:
        explanation_parts.append(f"{len(suspicious_links)} of the {len(links)} link(s) found use wording or shorteners typical of credential-harvesting pages.")
    if risky_attachments:
        explanation_parts.append(f"It includes {len(risky_attachments)} attachment(s) with executable file extensions, a common malware delivery method.")
    if not explanation_parts:
        explanation_parts.append("No spoofing indicators, phishing phrases, suspicious links, or risky attachments were found.")
    explanation_parts.append(f"Overall this results in a {risk_level} risk classification.")

    return {
        "risk_level": risk_level,
        "verdict": verdict,
        "metrics": metrics,
        "links": link_findings,
        "ai_explanation": " ".join(explanation_parts),
    }
