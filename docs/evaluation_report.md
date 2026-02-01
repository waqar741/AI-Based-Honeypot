# Project Evaluation Report

**Date:** 2026-02-01
**Version:** 1.0
**Philosophy:** “The goal of evaluation is not perfect detection, but controlled, explainable behavior under attack.”

---

## 1. Detection Accuracy (Qualitative)
We verified the system's behavior against specific test scenarios. The system correctly escalated responses based on risk levels.

| Scenario | Expected Decision | Observed | Result |
| :--- | :--- | :--- | :--- |
| **Normal Traffic** (Valid Login) | `ALLOW` | `ALLOW` | ✅ PASS |
| **SQL Injection** (`' OR 1=1`) | `DECEIVE` / `THROTTLE` | `DECEIVE` | ✅ PASS |
| **XSS** (`<script>`) | `MONITOR` / `DECEIVE` | `MONITOR` | ✅ PASS |
| **SSRF** (`http://127.0.0.1`) | `DECEIVE` | `DECEIVE` | ✅ PASS |
| **Brute Force** (High Rate) | `MONITOR` -> `THROTTLE` | `THROTTLE` | ✅ PASS |

> **Note:** We claim **no numeric detection accuracy %** (e.g., "99% accuracy") because this is a prototype honeypot, not a commercial WAF. Success is defined by *behavioral correctness*.

---

## 2. LLM Latency (Quantitative)
Analysis of `phi3` model inference on local hardware (CPU-only).

| Metric | Value (ms) | Value (seconds) |
| :--- | :--- | :--- |
| **Average Latency** | 24,599 ms | ~24.6 s |
| **Max Latency** | 32,567 ms | ~32.6 s |

> **Interpretation:** The average response time of ~24 seconds confirms that the LLM is the bottleneck. In a production environment, this would be offloaded to a GPU instance or an external API to achieve sub-second latency. For this proof-of-concept, the latency is acceptable as it occurs asynchronously for `MONITOR` decisions or delays the attacker in `THROTTLE` scenarios.

---

## 3. Decision Distribution
Breakdown of actions taken by the Decision Engine.

| Decision | Count | Description |
| :--- | :--- | :--- |
| **MONITOR** | 51 | Suspicious but low confidence (or forwarded traffic). |
| **ALLOW** | 9 | Safe, normal traffic. |
| **DECEIVE** | 6 | High-risk, active deception engaged. |
| **THROTTLE** | 5 | Behavioral rate limits or repeated attacks. |

---

## 4. Attack Type Frequency
Distribution of specific attack vectors detected.

| Attack Type | Count |
| :--- | :--- |
| **SQL Injection** | 8 |
| **SSRF** | 6 |
| **XSS** | 3 |

> Note: Counts include variations detected by both Legacy rules and the new `SecurityFilter`.

---

## 5. False Positive Handling
The system handles potential false positives through its tiered architecture:

1.  **Educational Queries**: A query like `search?q=drop table` might trigger a Regex rule (`SUSPICIOUS`).
2.  **LLM Context**: The LLM analyzes the context. If it sees it's a search term, it may downgrade the Risk Score.
3.  **Monitor Mode**: Even if flagged, the default low-risk decision is `MONITOR`, meaning the user is NOT blocked, but the event is logged for review.
4.  **No "Block"**: We do not implement a hard `BLOCK` by default, preventing denial-of-service for legitimate users. We prefer `THROTTLE` or `DECEIVE`.

---

## Conclusion
The gateway successfully demonstrates:
1.  **Multi-layer Defense**: Integrating Regex, LLM, and Behavioral signals.
2.  **Deception Capability**: Returning consistent fake data for SSRF and SQLi.
3.  **Observability**: Full visibility into decisions and latencies via the Dashboard.
