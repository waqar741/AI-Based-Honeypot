import sqlite3

def run_evaluation():
    conn = sqlite3.connect('data/honeypot.db')
    
    print("--- 2. LLM Latency ---")
    latency = conn.execute("SELECT AVG(llm_latency_ms), MAX(llm_latency_ms) FROM request_logs WHERE llm_latency_ms > 0").fetchone()
    print(f"Average: {latency[0]}")
    print(f"Max: {latency[1]}")
    
    print("\n--- 3. Decision Distribution ---")
    decisions = conn.execute("SELECT decision, COUNT(*) FROM request_logs GROUP BY decision").fetchall()
    print("Decision\tCount")
    for row in decisions:
        print(f"{row[0]}\t{row[1]}")
        
    print("\n--- 4. Attack Type Frequency ---")
    attacks = conn.execute("SELECT rule_matches, COUNT(*) FROM request_logs WHERE rule_matches != '' AND rule_matches IS NOT NULL GROUP BY rule_matches").fetchall()
    print("Rule Match\tCount")
    for row in attacks:
        print(f"{row[0]}\t{row[1]}")

    conn.close()

if __name__ == "__main__":
    run_evaluation()
