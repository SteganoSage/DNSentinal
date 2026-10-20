"""
Database layer for the DNSentinel Dashboard using SQLite.
Stores demo DNS query events, security alerts, and client states.
"""

import sqlite3
import os
from pathlib import Path

# Database path inside dashboard/backend/
DB_DIR = Path(__file__).resolve().parent.parent
DB_PATH = DB_DIR / "dnsentinel_demo.db"


def get_db_connection():
    """Returns a connection to the SQLite database with row_factory set to Row."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes tables in the SQLite database if they do not exist."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. DNS Queries Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS queries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        client_ip TEXT NOT NULL,
        client_name TEXT NOT NULL,
        qname TEXT NOT NULL,
        qtype TEXT NOT NULL,
        rcode TEXT NOT NULL,
        answer_count INTEGER NOT NULL,
        cache_status TEXT NOT NULL,
        latency_ms REAL NOT NULL,
        policy_action TEXT NOT NULL,
        block_reason TEXT,
        protocol TEXT NOT NULL
    )
    """)

    # 2. Security Alerts Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        domain TEXT NOT NULL,
        client_ip TEXT NOT NULL,
        threat_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        risk_score REAL NOT NULL,
        description TEXT NOT NULL,
        detection_evidence TEXT NOT NULL, -- JSON formatted list of reasons
        status TEXT NOT NULL DEFAULT 'Active',
        action_taken TEXT NOT NULL
    )
    """)

    # 3. Clients Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS clients (
        ip TEXT PRIMARY KEY,
        hostname TEXT NOT NULL,
        device_type TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Online',
        total_queries INTEGER NOT NULL DEFAULT 0,
        blocked_queries INTEGER NOT NULL DEFAULT 0,
        risk_level TEXT NOT NULL DEFAULT 'Low',
        last_seen TEXT NOT NULL
    )
    """)

    # 4. Demo Settings Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS demo_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()
