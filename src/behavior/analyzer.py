from datetime import datetime, timedelta
from src.database import get_connection
from src.rules.vectors import check_payload

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

def behavior_risk(ip, path, body=None):
    risk = 0
    detected_vectors = []

    # 1. Regex Vector Checks
    path_threats = check_payload(path)
    body_threats = check_payload(body) if body else []
    
    detected_vectors.extend(path_threats)
    detected_vectors.extend(body_threats)
    
    if detected_vectors:
        risk += 50 # High base risk for any detected vector

    # 2. Heuristics
    recent = count_recent_requests(ip)

    if recent > 10:
        risk += 2
    if recent > 25:
        risk += 4

    if is_login_path(path):
        risk += 3
        
    # Return both tuple (legacy support) or update caller to handle tuple
    # For compatibility with main.py which adds risk += behavior_risk(...), 
    # we should return risk int, but we also want to pass vector info.
    # Ideally main.py should receive vectors.
    # Let's verify main.py usage: "risk += behavior_risk(client_ip, path)"
    # We will stick to returning int here for safety, BUT we need a way to bubble up the vector name.
    # actually main.py doesn't capture the vector name from here currently.
    # We will fix main.py signature call in next step.
    
    return risk, list(set(detected_vectors))
