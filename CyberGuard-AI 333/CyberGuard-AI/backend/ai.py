"""
CyberGuard AI — ai.py
Rule-based cybersecurity assistant. Matches user questions against a
curated knowledge base of common topics. Designed so it can later be
swapped for a real LLM call (e.g. the Anthropic API) without changing
the calling code in app.py — just replace get_response()'s body.
"""

KNOWLEDGE_BASE = [
    {
        "keys": ["phishing"],
        "answer": (
            "Phishing is a social-engineering attack where someone impersonates a trusted source — "
            "a bank, coworker, or service — to trick you into revealing credentials, clicking a "
            "malicious link, or sending money. Red flags include urgent language, mismatched sender "
            "addresses, and links that don't match the real domain. Always verify through a separate, "
            "known channel before acting."
        ),
    },
    {
        "keys": ["sql injection", "sqli"],
        "answer": (
            "SQL Injection happens when an attacker inserts malicious SQL code into an input field that "
            "gets passed directly into a database query. If the application doesn't sanitize input, the "
            "attacker can read, modify, or delete data — sometimes bypassing login entirely. The fix is to "
            "always use parameterized queries or an ORM, never string-concatenate user input into SQL."
        ),
    },
    {
        "keys": ["secure my password", "password security", "strong password", "password tips"],
        "answer": (
            "To secure your passwords: use a unique password for every account, aim for 12+ characters "
            "mixing upper/lowercase, numbers and symbols, avoid dictionary words or personal info, and use "
            "a password manager so you never have to reuse or remember them. Turn on two-factor "
            "authentication wherever it's offered — it stops most account takeovers even if a password leaks."
        ),
    },
    {
        "keys": ["ransomware"],
        "answer": (
            "Ransomware is malware that encrypts a victim's files and demands payment for the decryption "
            "key. It typically spreads through phishing emails, malicious attachments, or unpatched "
            "software vulnerabilities. Defense relies on regular offline backups, keeping systems patched, "
            "restricting admin privileges, and training staff to spot the phishing emails that usually "
            "deliver it."
        ),
    },
    {
        "keys": ["xss", "cross-site scripting", "cross site scripting"],
        "answer": (
            "Cross-Site Scripting (XSS) lets an attacker inject malicious JavaScript into a page viewed by "
            "other users, often to steal session cookies or hijack accounts. It happens when user input is "
            "rendered in a page without proper escaping. Prevent it by escaping output, using "
            "Content-Security-Policy headers, and sanitizing any HTML you allow."
        ),
    },
    {
        "keys": ["malware"],
        "answer": (
            "Malware is any software designed to damage, disrupt, or gain unauthorized access to a system "
            "— including viruses, worms, trojans, spyware, and ransomware. Good defenses include keeping "
            "software patched, running reputable endpoint protection, avoiding untrusted downloads and "
            "attachments, and maintaining backups."
        ),
    },
    {
        "keys": ["brute force"],
        "answer": (
            "A brute-force attack tries many password or key combinations until one works. Mitigations "
            "include account lockouts after failed attempts, rate limiting, CAPTCHAs, strong minimum "
            "password requirements, and multi-factor authentication so a correct password guess alone "
            "isn't enough."
        ),
    },
    {
        "keys": ["2fa", "two-factor", "two factor", "mfa"],
        "answer": (
            "Multi-factor authentication (MFA) requires a second proof of identity beyond your password — "
            "like a code from an authenticator app, a hardware key, or a biometric. Even if your password "
            "is stolen or guessed, MFA stops most account takeovers. App-based or hardware-key MFA is "
            "stronger than SMS codes, which can be intercepted via SIM-swapping."
        ),
    },
    {
        "keys": ["vpn"],
        "answer": (
            "A VPN encrypts your internet traffic and routes it through a remote server, hiding your "
            "traffic from your local network or ISP and masking your IP address. It's useful on untrusted "
            "networks like public Wi-Fi, but it doesn't protect you from phishing, malware, or weak "
            "passwords — it's one layer of a broader security approach."
        ),
    },
    {
        "keys": ["firewall"],
        "answer": (
            "A firewall monitors and controls incoming and outgoing network traffic based on a set of "
            "security rules, acting as a barrier between a trusted internal network and untrusted external "
            "networks like the internet. It blocks unauthorized access while allowing legitimate "
            "communication through."
        ),
    },
    {
        "keys": ["ddos", "denial of service"],
        "answer": (
            "A Denial-of-Service (DoS) attack floods a system with traffic or requests until it can't serve "
            "legitimate users. A Distributed DoS (DDoS) does this from many sources at once, often a "
            "botnet, making it harder to block. Mitigations include traffic filtering, rate limiting, and "
            "CDN/DDoS-protection services that absorb the flood."
        ),
    },
    {
        "keys": ["social engineering"],
        "answer": (
            "Social engineering manipulates people rather than systems — using trust, urgency, or authority "
            "to get someone to reveal information or take an action they normally wouldn't. Phishing, "
            "pretexting, and baiting are all forms of it. The best defense is awareness: slow down, verify "
            "requests independently, and question unexpected urgency."
        ),
    },
    {
        "keys": ["directory traversal", "path traversal"],
        "answer": (
            "Directory traversal lets an attacker access files outside a web root by manipulating file "
            "path input (e.g. using '../../' sequences). It's prevented by validating and normalizing file "
            "paths server-side, using an allow-list of permitted files, and running the app with the least "
            "privilege necessary."
        ),
    },
    {
        "keys": ["command injection"],
        "answer": (
            "Command injection occurs when user input is passed unsanitized into a system shell command, "
            "letting an attacker run arbitrary OS commands. Prevent it by avoiding shell calls with user "
            "input entirely where possible, and otherwise using parameterized APIs (like subprocess with a "
            "list of args, never shell=True with concatenated strings)."
        ),
    },
]

FALLBACK_ANSWER = (
    "I don't have a specific answer for that yet, but I can help with topics like phishing, malware, "
    "ransomware, password security, SQL injection, XSS, brute-force attacks, MFA, VPNs, firewalls, "
    "directory traversal, command injection, and social engineering. Try asking about one of those, or "
    "run one of the scanner modules for a hands-on analysis."
)


def get_response(message: str) -> str:
    """Match the incoming message against the knowledge base and return an answer."""
    q = (message or "").lower()
    for entry in KNOWLEDGE_BASE:
        if any(key in q for key in entry["keys"]):
            return entry["answer"]
    return FALLBACK_ANSWER
