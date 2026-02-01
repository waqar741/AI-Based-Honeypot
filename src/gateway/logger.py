from src.database import get_connection
from src.models import RequestLog

def log_request(entry: RequestLog, verdict="", matches=""):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO request_logs
        (client_ip, method, path, query_params, user_agent, body, rule_verdict, rule_matches)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        entry.client_ip,
        entry.method,
        entry.path,
        entry.query_params,
        entry.user_agent,
        entry.body[:500],  # limit body size
        verdict,
        matches
    ))

    conn.commit()
    conn.close()
