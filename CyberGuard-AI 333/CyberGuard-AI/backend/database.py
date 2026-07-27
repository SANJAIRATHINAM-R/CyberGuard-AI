"""
CyberGuard AI — database.py
SQLite database setup, connection helper, and schema initialization.
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "cyberguard.db")


def get_db():
    """Return a SQLite connection with row access by column name."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Create all tables if they don't already exist. Safe to call on every boot."""
    conn = get_db()
    cur = conn.cursor()

    # No users table — the app is open access with no login or account
    # verification. user_id columns below are kept (always NULL) so the
    # schema can support accounts later without a migration.

    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER,
            module       TEXT NOT NULL,
            target       TEXT NOT NULL,
            risk_level   TEXT NOT NULL,
            verdict      TEXT NOT NULL,
            details_json TEXT,
            created_at   TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER,
            title      TEXT NOT NULL,
            summary    TEXT,
            risk_level TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS chat_history (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER,
            message    TEXT NOT NULL,
            reply      TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def log_scan(user_id, module, target, risk_level, verdict, details_json=""):
    conn = get_db()
    conn.execute(
        "INSERT INTO scans (user_id, module, target, risk_level, verdict, details_json, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, module, target, risk_level, verdict, details_json, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def get_recent_scans(user_id=None, limit=20):
    conn = get_db()
    if user_id:
        rows = conn.execute(
            "SELECT * FROM scans WHERE user_id = ? ORDER BY id DESC LIMIT ?", (user_id, limit)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]
