# End-to-End System Walkthrough & Viva Script

## 1. End-to-End System Walkthrough (Examiner Flow)

### Request Lifecycle (Speak while showing architecture diagram)
1.  **Interception**: “All HTTP requests pass through the application-layer gateway before reaching the backend.”
2.  **Normalization**: “We normalize paths, parameters, and payloads to detect obfuscation.”
3.  **Rule-Based Detection**: “High-confidence attacks are detected using deterministic regex rules.”
4.  **AI Advisory (Conditional)**: “Only suspicious requests are analyzed by a local offline LLM for semantic intent.”
5.  **Behavioral Analysis**: “Repeated requests and login attempts increase risk scores.”
6.  **Risk & Decision Engine**: “Final actions are selected using a policy-driven risk model.”
7.  **Deception or Forwarding**: “Malicious users receive consistent fake responses; benign users reach the real backend.”

*(Stop here. Let examiner nod.)*

---

## 2. Live Demo Plan (Step-by-Step)

### Demo Setup
*   **Terminal 1**: `python -m http.server 9000`
*   **Terminal 2**: `uvicorn src.main:app --port 8000`
*   **Browser**: `http://localhost:8000/dashboard`

### Demo Sequence
**Do not change this order.**

#### 🔹 Demo 1 – Normal User
*   **Action**: Visit `http://localhost:8000/home`
*   **Say**: “Benign traffic is forwarded transparently.”
*   **Show**: Dashboard row → `ALLOW`

#### 🔹 Demo 2 – SQL Injection
*   **Action**: URL `/login?user=admin' OR 1=1 --`
*   **Say**: “High-confidence SQL injection triggers deception.”
*   **Show**:
    *   Fake AI response in browser.
    *   Dashboard Decision = `DECEIVE` / `THROTTLE`.
    *   *Repeat request* -> Show consistent fake response.

#### 🔹 Demo 3 – XSS
*   **Action**: URL `/search?q=<script>alert(1)</script>`
*   **Say**: “Ambiguous attacks are monitored unless intent is confirmed.”

#### 🔹 Demo 4 – Brute Force
*   **Action**: Run `for i in {1..12}; do curl http://localhost:8000/login?user=test$i; done` (or manually refresh 10 times).
*   **Say**: “Behavioral analysis detects automation.”
*   **Show**: Dashboard escalation to `THROTTLE`.

---

## 3. Final Viva Script (Defense)

### Opening (30 seconds)
“This project implements an AI-assisted adaptive web honeypot that intercepts application-layer requests, classifies malicious intent using rules and a local LLM, and engages attackers through controlled deception while isolating the real backend.”

### Common Examiner Questions

**Q: Why use both rules and AI?**
A: “Rules provide fast, explainable detection; AI handles ambiguity.”

**Q: Why not cloud AI?**
A: “Offline LLM ensures privacy, independence, and academic reproducibility.”

**Q: Why deception instead of blocking?**
A: “Deception reduces false positives and allows attacker observation.”

**Q: Is AI making security decisions?**
A: “No. AI is strictly advisory; all actions are deterministic.”
