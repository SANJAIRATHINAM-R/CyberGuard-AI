"""
CyberGuard AI — logscan.py
Log analysis: scans Apache/Nginx/system log text line-by-line for common
attack patterns — SQL injection, XSS, brute force, directory traversal,
and command injection — and returns categorized findings with a risk score.
"""

import re
from collections import Counter, defaultdict
from urllib.parse import unquote

PATTERNS = {
    "SQL Injection": [
        re.compile(r"(\bunion\b.{0,20}\bselect\b)", re.IGNORECASE),
        re.compile(r"(\bor\b|\|\|)\s*'?\d+'?\s*=\s*'?\d+'?", re.IGNORECASE),
        re.compile(r"(\-\-|\#|/\*).{0,5}$"),
        re.compile(r"\bdrop\s+table\b", re.IGNORECASE),
        re.compile(r"\bexec(\s|\()+(xp|sp)_", re.IGNORECASE),
        re.compile(r"information_schema", re.IGNORECASE),
    ],
    "Cross-Site Scripting (XSS)": [
        re.compile(r"<script.*?>", re.IGNORECASE),
        re.compile(r"javascript\s*:", re.IGNORECASE),
        re.compile(r"onerror\s*=|onload\s*=", re.IGNORECASE),
        re.compile(r"%3Cscript", re.IGNORECASE),
    ],
    "Directory Traversal": [
        re.compile(r"\.\./|\.\.\\"),
        re.compile(r"%2e%2e%2f", re.IGNORECASE),
        re.compile(r"/etc/passwd"),
        re.compile(r"\bwin\.ini\b", re.IGNORECASE),
    ],
    "Command Injection": [
        re.compile(r";\s*(cat|ls|whoami|id|uname|wget|curl|nc|bash|sh)\b"),
        re.compile(r"\|\s*(cat|ls|whoami|id|nc|bash)\b"),
        re.compile(r"\$\(.*\)"),
        re.compile(r"`.*`"),
    ],
}

STATUS_CODE_REGEX = re.compile(r'"\s(\d{3})(?:\s|$)')
IP_REGEX = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})")
LOGIN_PATH_REGEX = re.compile(r"(login|signin|auth|wp-login)", re.IGNORECASE)

BRUTE_FORCE_THRESHOLD = 5  # failed attempts from the same IP against a login path


def _severity_for(category: str) -> str:
    return {
        "SQL Injection": "high",
        "Command Injection": "high",
        "Directory Traversal": "medium",
        "Cross-Site Scripting (XSS)": "medium",
        "Brute Force": "high",
    }.get(category, "low")


def analyze_log(text: str) -> dict:
    lines = [l for l in text.splitlines() if l.strip()]
    findings = []
    category_counts = Counter()

    # ---- Pattern-based detection per line ----
    for i, line in enumerate(lines, start=1):
        decoded_line = unquote(line)
        for category, patterns in PATTERNS.items():
            for pattern in patterns:
                if pattern.search(line) or pattern.search(decoded_line):
                    findings.append({
                        "severity": _severity_for(category),
                        "label": category,
                        "line": i,
                        "detail": line.strip()[:220],
                    })
                    category_counts[category] += 1
                    break  # one match per category per line is enough

    # ---- Brute force detection: repeated failed logins from same IP ----
    ip_login_failures = defaultdict(int)
    for line in lines:
        ip_match = IP_REGEX.match(line)
        status_match = STATUS_CODE_REGEX.search(line)
        if ip_match and LOGIN_PATH_REGEX.search(line) and status_match:
            status = status_match.group(1)
            if status in ("401", "403"):
                ip_login_failures[ip_match.group(1)] += 1

    for ip, count in ip_login_failures.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            findings.append({
                "severity": "high",
                "label": "Brute Force",
                "line": None,
                "detail": f"{count} failed login attempts from {ip}",
            })
            category_counts["Brute Force"] += 1

    # ---- Risk scoring ----
    high_count = sum(1 for f in findings if f["severity"] == "high")
    medium_count = sum(1 for f in findings if f["severity"] == "medium")

    if high_count > 0:
        risk_level = "high"
        verdict = f"{high_count} high-severity attack pattern(s) detected"
    elif medium_count > 0:
        risk_level = "medium"
        verdict = f"{medium_count} medium-severity pattern(s) detected"
    else:
        risk_level = "low"
        verdict = "No attack patterns detected in this log"

    metrics = [
        {"label": "Lines Analyzed", "value": str(len(lines)), "status": "ok"},
        {"label": "Total Findings", "value": str(len(findings)), "status": "bad" if findings else "ok"},
        {"label": "High Severity", "value": str(high_count), "status": "bad" if high_count else "ok"},
        {"label": "Categories Matched", "value": str(len(category_counts)) if category_counts else "0",
         "status": "warn" if category_counts else "ok"},
    ]

    if category_counts:
        top = ", ".join(f"{k} ({v})" for k, v in category_counts.most_common())
        explanation = (
            f"Analyzed {len(lines)} log line(s) and found {len(findings)} suspicious entr{'y' if len(findings)==1 else 'ies'} "
            f"across these categories: {top}. "
        )
        if high_count:
            explanation += "The high-severity findings suggest active attack attempts rather than incidental traffic — investigate the source IPs and consider blocking them at the firewall or WAF level."
        else:
            explanation += "These are lower-severity patterns; monitor for repetition but they may also be false positives from legitimate traffic containing special characters."
    else:
        explanation = f"Analyzed {len(lines)} log line(s) and found no known SQL injection, XSS, traversal, command injection, or brute-force patterns."

    return {
        "risk_level": risk_level,
        "verdict": verdict,
        "metrics": metrics,
        "findings": findings[:100],  # cap for very large logs
        "ai_explanation": explanation,
    }
