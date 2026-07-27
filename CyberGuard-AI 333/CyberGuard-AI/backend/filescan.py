"""
CyberGuard AI — filescan.py
File scanning: SHA-256 fingerprinting, file-type detection via magic bytes,
and heuristic risk-indicator checks (executables, macro-enabled Office docs,
archives containing executables, double extensions).
"""

import hashlib
import os
import re
import zipfile
import io

MAGIC_SIGNATURES = [
    (b"MZ", "Windows Executable (EXE/DLL)"),
    (b"\x7fELF", "Linux Executable (ELF)"),
    (b"PK\x03\x04", "ZIP-based Archive (ZIP/DOCX/APK/JAR)"),
    (b"%PDF", "PDF Document"),
    (b"\xd0\xcf\x11\xe0", "Legacy Office Document (DOC/XLS/PPT)"),
    (b"\x89PNG", "PNG Image"),
    (b"\xff\xd8\xff", "JPEG Image"),
    (b"Rar!", "RAR Archive"),
    (b"7z\xbc\xaf", "7-Zip Archive"),
]

DANGEROUS_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".vbs", ".jar", ".apk", ".msi", ".com", ".ps1"}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm"}
ARCHIVE_EXTENSIONS = {".zip", ".docx", ".xlsx", ".pptx", ".apk", ".jar"}

# Script-based threats (batch, VBScript, PowerShell, shell) have no binary
# "magic number" — they're plain text, so extension checks alone are easy to
# bypass by renaming the file. These patterns look at what the content
# actually does, regardless of what it's named or how it's labeled.
SUSPICIOUS_SCRIPT_PATTERNS = [
    (re.compile(r"powershell(\.exe)?\s+.*(-enc|-e\s|-nop|-w\s+hidden|-windowstyle\s+hidden)", re.IGNORECASE),
     "Obfuscated/hidden PowerShell execution"),
    (re.compile(r"invoke-expression|iex\s*\(", re.IGNORECASE), "PowerShell dynamic code execution (Invoke-Expression)"),
    (re.compile(r"wscript\.shell|createobject\s*\(\s*[\"']wscript", re.IGNORECASE), "VBScript shell automation object"),
    (re.compile(r"certutil.{0,20}-decode", re.IGNORECASE), "certutil used to decode a payload (common LOLBin technique)"),
    (re.compile(r"downloadstring|downloadfile|net\.webclient", re.IGNORECASE), "Script downloads remote content at runtime"),
    (re.compile(r"start-bitstransfer", re.IGNORECASE), "BITS transfer used to fetch a remote file"),
    (re.compile(r"del\s+/[fq]\s+.*%|rd\s+/s\s+/q", re.IGNORECASE), "Forced/silent file or directory deletion"),
    (re.compile(r"reg\s+add.{0,40}\\run", re.IGNORECASE), "Registry Run-key modification (common persistence technique)"),
    (re.compile(r"schtasks\s+/create", re.IGNORECASE), "Scheduled task creation (common persistence technique)"),
    (re.compile(r"-nop\s+-w\s+hidden|bypass\s+-c\b", re.IGNORECASE), "Execution-policy bypass with hidden window"),
]


def _looks_like_text(data: bytes) -> bool:
    """Cheap heuristic: mostly-printable, no null bytes in the first chunk."""
    sample = data[:4096]
    if b"\x00" in sample:
        return False
    if not sample:
        return False
    printable = sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126)
    return printable / len(sample) > 0.85


def _scan_script_content(data: bytes) -> list:
    """Content-based check for script threats — runs regardless of file
    extension, so renaming a .ps1 to .txt (or removing the extension
    entirely) doesn't bypass it."""
    if not _looks_like_text(data):
        return []
    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        return []
    findings = []
    for pattern, label in SUSPICIOUS_SCRIPT_PATTERNS:
        if pattern.search(text):
            findings.append(label)
    return findings


def _detect_type(data: bytes, filename: str) -> str:
    for sig, label in MAGIC_SIGNATURES:
        if data.startswith(sig):
            return label
    ext = os.path.splitext(filename)[1].lower()
    return f"Unknown ({ext or 'no extension'})"


def _check_double_extension(filename: str) -> bool:
    # e.g. "invoice.pdf.exe" — a classic malware-disguise trick
    parts = filename.lower().split(".")
    if len(parts) >= 3:
        second_last_ext = "." + parts[-2]
        last_ext = "." + parts[-1]
        return last_ext in DANGEROUS_EXTENSIONS and second_last_ext not in DANGEROUS_EXTENSIONS
    return False


def _scan_zip_contents(data: bytes) -> list:
    """If the file is a ZIP-based container, list any executables bundled inside."""
    findings = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
            for name in names:
                ext = os.path.splitext(name)[1].lower()
                if ext in DANGEROUS_EXTENSIONS:
                    findings.append(f"Archive contains executable: {name}")
            # Office macro indicator inside OOXML containers
            if any("vbaProject.bin" in n for n in names):
                findings.append("Document contains embedded VBA macro project (vbaProject.bin)")
    except zipfile.BadZipFile:
        pass
    return findings


def scan_file(filename: str, data: bytes) -> dict:
    sha256 = hashlib.sha256(data).hexdigest()
    size_bytes = len(data)
    file_type = _detect_type(data, filename)
    ext = os.path.splitext(filename)[1].lower()

    findings = []

    if ext in DANGEROUS_EXTENSIONS or data.startswith(b"MZ") or data.startswith(b"\x7fELF"):
        findings.append({"severity": "high", "label": "Executable File",
                          "detail": f"This file is a native executable ({file_type}). Only run executables from sources you fully trust."})

    if ext in MACRO_EXTENSIONS:
        findings.append({"severity": "high", "label": "Macro-Enabled Document",
                          "detail": f"The '{ext}' extension indicates this document can run embedded macros, a common malware delivery method."})

    if _check_double_extension(filename):
        findings.append({"severity": "high", "label": "Double Extension Disguise",
                          "detail": f"'{filename}' uses a double extension, a classic trick to disguise an executable as a harmless file."})

    if ext in ARCHIVE_EXTENSIONS or data.startswith(b"PK\x03\x04"):
        zip_findings = _scan_zip_contents(data)
        for zf in zip_findings:
            findings.append({"severity": "high" if "executable" in zf.lower() else "medium",
                              "label": "Archive Content Risk", "detail": zf})

    # Content-based script detection — runs on ANY text-like file regardless
    # of its extension, so this isn't fooled by renaming a .ps1/.bat/.vbs to
    # something innocuous-looking.
    script_findings = _scan_script_content(data)
    for sf in script_findings:
        findings.append({"severity": "high", "label": "Suspicious Script Behavior", "detail": sf})

    if size_bytes == 0:
        findings.append({"severity": "medium", "label": "Empty File", "detail": "The file has no content."})

    if not findings:
        findings.append({"severity": "low", "label": "No Indicators Found",
                          "detail": "No executable signatures, macros, or archive risks were detected in this file."})

    high_count = sum(1 for f in findings if f["severity"] == "high")
    medium_count = sum(1 for f in findings if f["severity"] == "medium")

    if high_count > 0:
        risk_level = "high"
        verdict = "This file shows strong risk indicators"
    elif medium_count > 0:
        risk_level = "medium"
        verdict = "This file has some risk indicators worth reviewing"
    else:
        risk_level = "low"
        verdict = "This file appears clean based on static analysis"

    metrics = [
        {"label": "File Type", "value": file_type, "status": "warn" if "Unknown" in file_type else "ok"},
        {"label": "File Size", "value": f"{size_bytes:,} bytes", "status": "ok"},
        {"label": "High-Severity Findings", "value": str(high_count), "status": "bad" if high_count else "ok"},
        {"label": "Extension", "value": ext or "none", "status": "bad" if ext in DANGEROUS_EXTENSIONS else "ok"},
    ]

    explanation = (
        f"Static analysis of '{filename}' ({size_bytes:,} bytes, identified as {file_type}) found "
        f"{len(findings)} indicator(s): {high_count} high-severity and {medium_count} medium-severity. "
    )
    if risk_level == "low":
        explanation += "No signature-based or content-based red flags were found. Note that static analysis can't guarantee a file is completely safe — heavily obfuscated or entirely novel scripts may not match known patterns, so always scan with updated antivirus software before opening unfamiliar files."
    else:
        explanation += "Review the findings below before opening this file, and consider scanning it with a dedicated antivirus engine for a second opinion."

    return {
        "risk_level": risk_level,
        "verdict": verdict,
        "sha256": sha256,
        "metrics": metrics,
        "findings": findings,
        "ai_explanation": explanation,
    }
