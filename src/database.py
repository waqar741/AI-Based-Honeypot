import sqlite3
from pathlib import Path

DB_PATH = Path("data/honeypot.db")

def get_connection():
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    # Base table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS request_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            client_ip TEXT,
            method TEXT,
            path TEXT,
            query_params TEXT,
            user_agent TEXT,
            body TEXT
        )
    """)
    
    # Migration 1: Rule Engine
    try:
        cursor.execute("ALTER TABLE request_logs ADD COLUMN rule_verdict TEXT")
        cursor.execute("ALTER TABLE request_logs ADD COLUMN rule_matches TEXT")
    except sqlite3.OperationalError:
        pass 

    # Migration 2: LLM Integration
    try:
        cursor.execute("ALTER TABLE request_logs ADD COLUMN llm_verdict TEXT")
        cursor.execute("ALTER TABLE request_logs ADD COLUMN llm_latency_ms INTEGER")
    except sqlite3.OperationalError:
        pass

    conn.commit()
    conn.close()
