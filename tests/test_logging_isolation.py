from src.database import init_db, get_connection
from src.gateway.logger import log_request
from src.models import RequestLog
import os

def test_logging():
    # Setup
    if os.path.exists("data/honeypot.db"):
        os.remove("data/honeypot.db")
    
    print("Run init_db()...")
    init_db()
    
    # Test Data
    entry = RequestLog(
        client_ip="127.0.0.1",
        method="GET",
        path="/test-log",
        query_params="q=1",
        user_agent="TestBot",
        body=""
    )
    
    print("Log request...")
    log_request(entry)
    
    # Verify
    print("Verify DB content...")
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT client_ip, path FROM request_logs")
    row = cursor.fetchone()
    conn.close()
    
    if row and row[0] == "127.0.0.1" and row[1] == "/test-log":
        print("SUCCESS: Log found in DB.")
    else:
        print(f"FAILURE: Log not found or incorrect. Got: {row}")

if __name__ == "__main__":
    test_logging()
