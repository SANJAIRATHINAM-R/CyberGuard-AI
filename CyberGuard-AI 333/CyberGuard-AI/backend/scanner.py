"""
CyberGuard AI — scanner.py
Website scanning: HTTPS check, domain age (WHOIS), blacklist heuristics,
redirect-chain inspection, and an aggregate risk score with AI explanation.

Network calls (requests / whois) are wrapped in try/except so the scanner
still returns a useful heuristic result even when offline or when the
optional `python-whois` package isn't installed.
"""

import re
import socket
from datetime import datetime
from urllib.parse import urlparse

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

try:
    import whois as whois_lib
except ImportError:  # pragma: no cover
    whois_lib = None


SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "account", "bank", "paypal",
    "signin", "confirm", "billing", "free", "bonus", "gift", "prize",
]

# A tiny illustrative blacklist for demo purposes — in production this would
# call a real threat-intel feed (Google Safe Browsing, VirusTotal, etc.)
DEMO_BLACKLIST_PATTERNS = [
    r"paypa1", r"g00gle", r"micros0ft", r"amaz0n", r"faceb00k", r"appleid-verify",
]


def _normalize_url(raw_url: str) -> str:
    if not re.match(r"^https?://", raw_url, re.IGNORECASE):
        return "http://" + raw_url
    return raw_url


def _check_https(url: str) -> dict:
    is_https = url.lower().startswith("https://")
    return {"label": "HTTPS", "value": "Enabled" if is_https else "Missing", "status": "ok" if is_https else "bad"}


def _check_domain_age(hostname: str) -> dict:
    if whois_lib is None:
        return {"label": "Domain Age", "value": "Check unavailable (install python-whois)", "status": "warn"}
    try:
        w = whois_lib.whois(hostname)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if not created:
            return {"label": "Domain Age", "value": "Unknown", "status": "warn"}
        age_days = (datetime.utcnow() - created).days
        if age_days < 180:
            return {"label": "Domain Age", "value": f"{age_days} days (very new)", "status": "bad"}
        if age_days < 365:
            return {"label": "Domain Age", "value": f"{age_days} days", "status": "warn"}
        years = age_days // 365
        return {"label": "Domain Age", "value": f"{years}+ years", "status": "ok"}
    except Exception:
        return {"label": "Domain Age", "value": "Lookup failed", "status": "warn"}


def _check_blacklist(hostname: str) -> dict:
    for pattern in DEMO_BLACKLIST_PATTERNS:
        if re.search(pattern, hostname, re.IGNORECASE):
            return {"label": "Blacklist Status", "value": "Matches known phishing pattern", "status": "bad"}
    return {"label": "Blacklist Status", "value": "Not listed", "status": "ok"}


def _check_keywords(hostname: str) -> dict:
    hits = [k for k in SUSPICIOUS_KEYWORDS if k in hostname.lower()]
    if hits:
        return {"label": "Suspicious Keywords", "value": ", ".join(hits), "status": "bad"}
    return {"label": "Suspicious Keywords", "value": "None found", "status": "ok"}


def _check_redirects(url: str) -> dict:
    if requests is None:
        return {"label": "Redirect Chain", "value": "Check unavailable (install requests)", "status": "warn"}
    try:
        resp = requests.get(url, timeout=5, allow_redirects=True)
        hops = len(resp.history)
        if hops == 0:
            return {"label": "Redirect Chain", "value": "No redirects", "status": "ok"}
        if hops <= 2:
            return {"label": "Redirect Chain", "value": f"{hops} redirect(s)", "status": "warn"}
        return {"label": "Redirect Chain", "value": f"{hops} redirects (excessive)", "status": "bad"}
    except Exception:
        return {"label": "Redirect Chain", "value": "Could not reach host", "status": "warn"}


def scan_website(raw_url: str) -> dict:
    url = _normalize_url(raw_url)
    hostname = urlparse(url).hostname or raw_url

    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))
    many_subdomains = hostname.count(".") > 2
    many_hyphens = hostname.count("-") >= 2

    metrics = [
        _check_https(url),
        _check_domain_age(hostname),
        _check_blacklist(hostname),
        _check_keywords(hostname),
    ]

    risk_points = 0
    for m in metrics:
        if m["status"] == "bad":
            risk_points += 25
        elif m["status"] == "warn":
            risk_points += 8
    if is_ip:
        risk_points += 30
    if many_subdomains:
        risk_points += 10
    if many_hyphens:
        risk_points += 10

    if risk_points >= 50:
        risk_level = "high"
        verdict = "This site shows multiple high-risk indicators"
    elif risk_points >= 20:
        risk_level = "medium"
        verdict = "This site has some suspicious characteristics"
    else:
        risk_level = "low"
        verdict = "This site appears safe based on available checks"

    bad_findings = [m["label"] for m in metrics if m["status"] == "bad"]
    explanation_parts = [f"Analyzing {hostname}:"]
    if bad_findings:
        explanation_parts.append("Flagged issues include " + ", ".join(bad_findings) + ".")
    else:
        explanation_parts.append("No major red flags were found in the checks performed.")
    if is_ip:
        explanation_parts.append("The address uses a raw IP instead of a domain name, which is unusual for legitimate sites.")
    explanation_parts.append(f"Overall this results in a {risk_level} risk classification.")
    explanation_parts.append("Always verify the sender and avoid entering credentials on sites you don't fully trust.")

    return {
        "risk_level": risk_level,
        "verdict": verdict,
        "metrics": metrics,
        "ai_explanation": " ".join(explanation_parts),
    }
