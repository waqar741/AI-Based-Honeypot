import requests
import time
import sqlite3

URL = "http://localhost:8000/fetch?url=http://127.0.0.1/admin"
DB_PATH = "data/honeypot.db"

print(f"Sending request to {URL}...")
try:
    resp = requests.get(URL, timeout=10)
    print(f"Status: {resp.status_code}")
    print(f"Body: {resp.text[:100]}")
except Exception as e:
    print(f"Error: {e}")

time.sleep(2)

print("Checking DB...")
conn = sqlite3.connect(DB_PATH)
rows = conn.execute("SELECT path, rule_matches, rule_verdict FROM request_logs WHERE path LIKE '%fetch%' ORDER BY id DESC LIMIT 1").fetchall()
print(f"Logs: {rows}")
conn.close()
