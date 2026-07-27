"""
CyberGuard AI — app.py
Main Flask application: serves the frontend and exposes JSON API endpoints
for each security module. No login or account verification — every page
and API endpoint is open access.

Run with:
    pip install flask requests python-whois --break-system-packages
    python app.py
Then open http://127.0.0.1:5000
"""

import os
from datetime import datetime

from flask import Flask, request, jsonify, send_from_directory

from database import init_db, get_db, log_scan, get_recent_scans
from password import analyze_password
from scanner import scan_website
from ai import get_response as chatbot_response
from emailscan import analyze_email
from filescan import scan_file
from logscan import analyze_log

FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")

init_db()


# ==========================================================================
# Frontend routes — serve the static HTML/CSS/JS pages
# ==========================================================================
@app.route("/")
def serve_index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:filename>")
def serve_static(filename):
    """Serve any top-level HTML file, or files under /css, /js, /images, /icons."""
    full_path = os.path.join(FRONTEND_DIR, filename)
    if os.path.isfile(full_path):
        return send_from_directory(FRONTEND_DIR, filename)
    return jsonify({"message": "Not found"}), 404


# ==========================================================================
# Module API — Password Checker
# ==========================================================================
@app.route("/api/password-check", methods=["POST"])
def password_check():
    data = request.get_json(silent=True) or {}
    pw = data.get("password") or ""
    if not pw:
        return jsonify({"message": "Password is required"}), 400

    result = analyze_password(pw)
    log_scan(None, "Password Checker", "•" * min(len(pw), 12), result["risk_level"], result["verdict"])
    return jsonify(result)


# ==========================================================================
# Module API — Website Scanner
# ==========================================================================
@app.route("/api/scan-website", methods=["POST"])
def scan_website_route():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"message": "URL is required"}), 400

    result = scan_website(url)
    log_scan(None, "Website Scanner", url, result["risk_level"], result["verdict"])
    return jsonify(result)


# ==========================================================================
# Module API — AI Chatbot
# ==========================================================================
@app.route("/api/chatbot", methods=["POST"])
def chatbot():
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"message": "Message is required"}), 400

    reply = chatbot_response(message)

    conn = get_db()
    conn.execute(
        "INSERT INTO chat_history (user_id, message, reply, created_at) VALUES (NULL, ?, ?, ?)",
        (message, reply, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()

    return jsonify({"reply": reply})


# ==========================================================================
# Module API — Email Analyzer
# ==========================================================================
@app.route("/api/analyze-email", methods=["POST"])
def analyze_email_route():
    raw_bytes = None
    raw_text = None

    if "file" in request.files and request.files["file"].filename:
        raw_bytes = request.files["file"].read()
        target = request.files["file"].filename
    else:
        data = request.get_json(silent=True) or {}
        raw_text = data.get("raw") or ""
        target = "Pasted email content"
        if not raw_text.strip():
            return jsonify({"message": "Provide an .eml file or paste email content"}), 400

    result = analyze_email(raw_bytes=raw_bytes, raw_text=raw_text)
    log_scan(None, "Email Analyzer", target, result["risk_level"], result["verdict"])
    return jsonify(result)


# ==========================================================================
# Module API — File Scanner
# ==========================================================================
@app.route("/api/scan-file", methods=["POST"])
def scan_file_route():
    if "file" not in request.files or not request.files["file"].filename:
        return jsonify({"message": "No file uploaded"}), 400

    uploaded = request.files["file"]
    data = uploaded.read()
    if len(data) > 25 * 1024 * 1024:
        return jsonify({"message": "File exceeds the 25MB limit"}), 400

    result = scan_file(uploaded.filename, data)
    log_scan(None, "File Scanner", uploaded.filename, result["risk_level"], result["verdict"])
    return jsonify(result)


# ==========================================================================
# Module API — Log Analyzer
# ==========================================================================
@app.route("/api/analyze-log", methods=["POST"])
def analyze_log_route():
    if "file" in request.files and request.files["file"].filename:
        text = request.files["file"].read().decode("utf-8", errors="ignore")
        target = request.files["file"].filename
    else:
        data = request.get_json(silent=True) or {}
        text = data.get("raw") or ""
        target = "Pasted log content"
        if not text.strip():
            return jsonify({"message": "Provide a log file or paste log content"}), 400

    result = analyze_log(text)
    log_scan(None, "Log Analyzer", target, result["risk_level"], result["verdict"])
    return jsonify(result)


# ==========================================================================
# Dashboard data — recent activity feed
# ==========================================================================
@app.route("/api/recent-scans", methods=["GET"])
def recent_scans():
    scans = get_recent_scans(limit=20)
    return jsonify({"scans": scans})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
