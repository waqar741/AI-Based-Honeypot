from src.database import get_connection

def fetch_recent_logs(limit=50):
    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT timestamp, path, rule_verdict, llm_verdict,
                risk_score, decision, deception_response
            FROM request_logs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = cur.fetchall()
    except Exception:
        rows = []
        
    conn.close()
    return rows
