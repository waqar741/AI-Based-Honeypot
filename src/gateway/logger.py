from src.database import get_connection
from src.models import RequestLog

def log_request(entry: RequestLog, verdict="", matches="", llm_verdict="", llm_latency=0):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO request_logs
        (client_ip, method, path, query_params, user_agent, body, rule_verdict, rule_matches, llm_verdict, llm_latency_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        entry.client_ip,
        entry.method,
        entry.path,
        entry.query_params,
        entry.user_agent,
        entry.body[:500],
        verdict,
        matches,
        llm_verdict,
        llm_latency
    ))

    conn.commit()
    conn.close()
