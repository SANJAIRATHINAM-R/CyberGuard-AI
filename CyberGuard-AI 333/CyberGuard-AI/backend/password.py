"""
CyberGuard AI — password.py
Password strength analysis: entropy calculation, crack-time estimation,
and human-readable suggestions.
"""

import math
import re

COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "111111", "12345678",
    "abc123", "password1", "iloveyou", "admin", "welcome", "monkey",
    "letmein", "dragon", "football", "baseball", "sunshine", "master",
}


def _charset_size(pw: str) -> int:
    size = 0
    if re.search(r"[a-z]", pw):
        size += 26
    if re.search(r"[A-Z]", pw):
        size += 26
    if re.search(r"\d", pw):
        size += 10
    if re.search(r"[^A-Za-z0-9]", pw):
        size += 32
    return size or 1


def _estimate_crack_time(entropy_bits: float, guesses_per_second: float = 1e9) -> str:
    """Assume an offline attacker at ~1 billion guesses/sec (modern GPU rig)."""
    guesses = 2 ** entropy_bits
    seconds = guesses / guesses_per_second

    if seconds < 1:
        return "Instantly"
    if seconds < 60:
        return f"{round(seconds)} seconds"
    if seconds < 3600:
        return f"{round(seconds / 60)} minutes"
    if seconds < 86400:
        return f"{round(seconds / 3600)} hours"
    if seconds < 31536000:
        return f"{round(seconds / 86400)} days"
    years = seconds / 31536000
    if years > 1e6:
        return "Millions of years"
    return f"{round(years):,} years"


def analyze_password(pw: str) -> dict:
    """Return a full strength report for the given password string."""
    length = len(pw)
    charset = _charset_size(pw)
    entropy = length * math.log2(charset) if length else 0.0
    crack_time = _estimate_crack_time(entropy)

    is_common = pw.lower() in COMMON_PASSWORDS
    has_repeats = bool(re.search(r"(.)\1{2,}", pw))
    has_sequence = bool(re.search(r"(012|123|234|345|456|567|678|789|abc|bcd|cde)", pw.lower()))

    # Base score 0-5 from composition
    score = 0
    if length >= 8:
        score += 1
    if length >= 12:
        score += 1
    if re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw):
        score += 1
    if re.search(r"\d", pw):
        score += 1
    if re.search(r"[^A-Za-z0-9]", pw):
        score += 1

    # Penalties
    if is_common:
        score = 0
    if has_repeats:
        score = max(0, score - 1)
    if has_sequence:
        score = max(0, score - 1)

    if score <= 1:
        risk_level = "high"
        verdict = "Weak password — easily crackable"
    elif score <= 3:
        risk_level = "medium"
        verdict = "Moderate password — could be stronger"
    else:
        risk_level = "low"
        verdict = "Strong password"

    charsets_used = []
    if re.search(r"[a-z]", pw):
        charsets_used.append("lowercase")
    if re.search(r"[A-Z]", pw):
        charsets_used.append("uppercase")
    if re.search(r"\d", pw):
        charsets_used.append("digits")
    if re.search(r"[^A-Za-z0-9]", pw):
        charsets_used.append("symbols")

    suggestions = []
    if length < 12:
        suggestions.append("Use at least 12 characters")
    if "uppercase" not in charsets_used or "lowercase" not in charsets_used:
        suggestions.append("Mix uppercase and lowercase letters")
    if "digits" not in charsets_used:
        suggestions.append("Add numbers")
    if "symbols" not in charsets_used:
        suggestions.append("Add special characters (!@#$%)")
    if has_repeats:
        suggestions.append("Avoid repeating the same character multiple times in a row")
    if has_sequence:
        suggestions.append("Avoid predictable sequences like '123' or 'abc'")
    if is_common:
        suggestions.append("This is one of the most commonly leaked passwords — never use it")
    if not suggestions:
        suggestions.append("Great job — this password meets all strength criteria")

    ai_explanation = (
        f"This password has an estimated entropy of {entropy:.1f} bits, calculated from its length "
        f"({length} characters) and the variety of character types used. {verdict}. "
        f"Assuming an attacker uses modern offline cracking hardware (~1 billion guesses/second), "
        f"it would take approximately {crack_time} to guess through brute force."
    )
    if is_common:
        ai_explanation += " This password also appears in common leaked-password lists, making it crackable almost instantly regardless of entropy."

    return {
        "risk_level": risk_level,
        "verdict": verdict,
        "entropy": f"{entropy:.1f} bits",
        "length": length,
        "charsets": ", ".join(charsets_used) if charsets_used else "none",
        "crack_time": crack_time,
        "ai_explanation": ai_explanation,
        "suggestions": suggestions,
    }
