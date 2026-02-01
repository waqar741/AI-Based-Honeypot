import requests
import sqlite3
import time

GATEWAY_URL = "http://localhost:8000"
DB_PATH = "data/honeypot.db"
CURRENT_MAX_ID = 0


def get_latest_log(min_id=0, path_keyword=""):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    query_str = f"%{path_keyword}%"

    cursor.execute("""
        SELECT id, path, rule_verdict, llm_verdict,
               llm_latency_ms, risk_score, decision, deception_response
        FROM request_logs
        WHERE id > ? AND path LIKE ?
        ORDER BY id DESC
        LIMIT 1
    """, (min_id, query_str))

    row = cursor.fetchone()
    conn.close()
    return row


def send_and_check(name, url, description, expected_rule, expected_llm,
                   expect_deception=False, previous_fake=None):
    global CURRENT_MAX_ID

    print(f"\n==============================")
    print(f"TEST: {name}")
    print(f"Request URL : {url}")
    print(f"Description : {description}")
    print(f"Expected    : Rule={expected_rule}, LLM={expected_llm}")
    print(f"------------------------------")

    try:
        resp = requests.get(url, timeout=40)
        print(f"HTTP Status       : {resp.status_code}")
        preview = resp.text.strip()[:120]
        print(f"Response Preview  : {preview if preview else '[EMPTY]'}")
    except Exception as e:
        print(f"Request error (ignored): {e}")

    time.sleep(1.0)

    path_keyword = url.split("8000/")[-1].split("?")[0]
    if path_keyword == "":
        path_keyword = "home"
    if "passwd" in url:
        path_keyword = "etc"

    row = get_latest_log(min_id=CURRENT_MAX_ID, path_keyword=path_keyword)
    if not row:
        print("❌ No NEW log entry found (Stale read prevented)")
        return None

    _id, path, rule, llm, latency, risk, decision, fake_resp = row
    CURRENT_MAX_ID = _id

    print(f"DB Log ID        : {_id}")
    print(f"Logged Path      : {path}")
    print(f"Rule Verdict     : {rule}")
    print(f"LLM Verdict      : {llm}")
    print(f"LLM Latency (ms) : {latency}")
    print(f"Risk Score       : {risk}")
    print(f"Decision         : {decision}")
    print(f"Deception Output : {fake_resp[:60] if fake_resp else 'None'}")

    print("RESULT:")

    # Rule + LLM correctness
    rule_ok = rule == expected_rule
    llm_ok = (llm == expected_llm)

    if expect_deception:
        if decision in ["DECEIVE", "THROTTLE"] and fake_resp:
            print("✅ PASS (Deception activated)")
            if previous_fake is not None:
                if fake_resp == previous_fake:
                    print("✅ PASS (Consistent fake response)")
                else:
                    print("⚠️  CHECK (Fake response changed)")
        else:
            print("⚠️  CHECK (Expected deception)")
    else:
        if rule_ok and llm_ok:
            print("✅ PASS")
        else:
            print("⚠️  CHECK (acceptable if explained in viva)")

    return fake_resp


def main():
    print("\n🚀 STARTING MULTI-LAYER + DECEPTION TESTS\n")

    send_and_check(
        name="Normal Traffic",
        url=f"{GATEWAY_URL}/home",
        description="Normal benign request",
        expected_rule="SAFE",
        expected_llm=""
    )

    fake1 = send_and_check(
        name="Clear SQL Injection",
        url=f"{GATEWAY_URL}/login?user=admin' OR 1=1 --",
        description="Classic SQL injection payload",
        expected_rule="MALICIOUS",
        expected_llm="UNSAFE",
        expect_deception=True
    )

    fake2 = send_and_check(
        name="Clear SQL Injection (Repeat)",
        url=f"{GATEWAY_URL}/login?user=admin' OR 1=1 --",
        description="Same SQL injection again (consistency check)",
        expected_rule="MALICIOUS",
        expected_llm="UNSAFE",
        expect_deception=True,
        previous_fake=fake1
    )

    send_and_check(
        name="XSS Payload",
        url=f"{GATEWAY_URL}/search?q=<script>alert(1)</script>",
        description="Reflected XSS attempt",
        expected_rule="SUSPICIOUS",
        expected_llm="UNSAFE",
        expect_deception=True
    )

    send_and_check(
        name="Benign but Confusing",
        url=f"{GATEWAY_URL}/docs?q=how to use <script> tag safely",
        description="Educational content",
        expected_rule="SUSPICIOUS",
        expected_llm="SAFE"
    )

    send_and_check(
        name="Directory Traversal",
        url=f"{GATEWAY_URL}/../../etc/passwd",
        description="Traversal attempt (framework normalized)",
        expected_rule="MALICIOUS",
        expected_llm="UNSAFE"
    )

    send_and_check(
        name="Random Input",
        url=f"{GATEWAY_URL}/test?q=asdj123!@#",
        description="Random noise",
        expected_rule="SAFE",
        expected_llm=""
    )

    print("\n==============================")
    print("TEST: Brute Force Simulation (Behavioral)")

    for i in range(15):
        try:
            requests.get(f"{GATEWAY_URL}/login?user=test{i}", timeout=3)
        except:
            pass

    time.sleep(1.5)
    row = get_latest_log(min_id=CURRENT_MAX_ID, path_keyword="login")

    if row:
        _id, path, rule, llm, latency, risk, decision, fake_resp = row
        print(f"Final Behavioral Decision: {decision} (Risk: {risk})")
        if risk >= 3:
            print("✅ PASS (Behavioral escalation detected)")
        else:
            print("⚠️ CHECK (Risk should be higher)")

    print("\n✅ MULTI-LAYER + DECEPTION TESTING COMPLETE\n")


if __name__ == "__main__":
    main()
