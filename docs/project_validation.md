# Project Validation & Viva Defense

## 1. Why this is a Honeypot (Not IDS / IPS)
This distinction is critical for understanding the system's value proposition.

| System | Behavior | Philosophy |
| :--- | :--- | :--- |
| **IDS** | Detects & Alerts | Passive monitoring. |
| **IPS** | Detects & Blocks | Prevention-first. |
| **This System** | **Detects, Deceives, & Logs** | **Intelligence-first.** |

**Validation Statement:**
“The system prioritizes deception and observation over prevention, which is the defining characteristic of a honeypot. Unlike an IPS that instantly drops connection, this gateway engages the attacker to gather forensic data.”

---

## 2. Ethical Boundaries
We adhere to strict ethical guidelines to ensure this tool is a defensive asset, not a liability.

### Ethical Principles
*   ❌ **No Real Data Exposure**: Use of synthetic/mock data only.
*   ❌ **No Account Compromise**: Vulnerabilities are simulated; no real accounts exist.
*   ❌ **No Command Execution**: Attackers cannot execute code on the host.
*   ❌ **No Attacker Fingerprinting**: We do not aggressively probe the attacker (no hack-back).

**Ethics Statement:**
“The honeypot does not engage in counter-attacks or exploitation and strictly limits interaction to controlled deception and logging.”

---

## 3. System Limitations (Honest Assessment)
These limitations are accepted constraints of the academic prototype scope.

### Technical Limitations
1.  **Local LLM Latency**: Offline inference with `phi3` on CPU takes seconds. Production would use GPU/API.
2.  **Regex Blind Spots**: Novel attacks not matching static patterns may bypass the fast path (mitigated by LLM).
3.  **Path Normalization**: Framework-level normalization might mask some raw traversal attempts.
4.  **No TLS Termination**: We assume SSL/TLS is handled by an upstream load balancer (Nginx/AWS logic).

### Design Limitations
1.  **Concurrency**: SQLite limits write concurrency compared to PostgreSQL.
2.  **Prototype Backend**: The backend is a static demonstration service.

**Validation Statement:**
“These limitations are documented and accepted due to the academic scope of the project. The architecture allows these components (DB, LLM) to be swapped for production-grade alternatives.”

---

## 4. Future Scope
The following enhancements logically extend the current work:

1.  **SIEM Integration**: Replace SQLite with ELK Stack or Splunk forwarding.
2.  **Session Correlation**: Track multi-step attacks across different IPs.
3.  **Fine-tuned LLM**: Train a smaller model (BERT/RoBERTa) specifically for HTTP payload classification to reduce latency.
4.  **Richer Deception**: Script multi-stage login flows (2FA mocking) to waste more attacker time.
5.  **Containerization**: Dockerize the Gateway + Ollama for portable deployment.

---

## 5. Defense Against Common Questions

**Q: "Is this system dangerous?"**
A: "No. It does not execute any attacker-controlled logic. It parses inputs as strings and decides a response."

**Q: "Can attackers be harmed?"**
A: "No. The system only provides fake responses. No counter-offensive measures are employed."

**Q: "Why not block everything?"**
A: "Blocking increases false positives (blocking legitimate users). Deception allows for safer observation and high-confidence verification before banning."
