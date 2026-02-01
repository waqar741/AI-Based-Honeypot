from datetime import datetime, timedelta
from src.database import get_connection

LOGIN_PATH_KEYWORDS = ["login", "signin", "auth"]

def is_login_path(path: str):
    return any(k in path.lower() for k in LOGIN_PATH_KEYWORDS)

def count_recent_requests(ip, minutes=1):
    conn = get_connection()
    cur = conn.cursor()
    since = datetime.utcnow() - timedelta(minutes=minutes)

    try:
        cur.execute("""
            SELECT COUNT(*) FROM request_logs
            WHERE client_ip = ? AND timestamp >= ?
        """, (ip, since))
        count = cur.fetchone()[0]
    except Exception:
        count = 0
        
    conn.close()
    return count

def behavior_risk(ip, path):
    risk = 0

    recent = count_recent_requests(ip)

    if recent > 10:
        risk += 2
    if recent > 25:
        risk += 4

    if is_login_path(path):
        risk += 3

    return risk
