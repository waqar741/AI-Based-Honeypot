# System Architecture

## Gateway Positioning
The AI-Honeypot-Gateway is positioned as a **Reverse Proxy** at the network edge, directly facing the internet. It acts as the primary entry point for all client traffic, abstracting the actual backend infrastructure. This "Man-in-the-Middle" position enables complete visibility and control over both incoming requests and outgoing responses.

## Multi-Layer Analysis Flow
The detection logic is built on a "Defense in Depth" strategy, processing requests through 5 distinct layers:

### 1. Rule-Based Engine (Fast Path)
*   **Purpose**: Rapidly identify and filter obvious, high-volume automated attacks.
*   **Mechanism**: Uses compiled Regular Expressions (Regex) via `SecurityFilter`.
*   **Targets**: SQLi, XSS, SSRF, LFI, XXE, Web Shells, Scanners.
*   **Latency**: Microseconds.

### 2. LLM-Assisted Analysis (Slow Path)
*   **Purpose**: Detect complex, obfuscated, or context-specific attacks that evade static rules.
*   **Mechanism**: A local Large Language Model (`phi3` via Ollama) analyzes suspicious requests identified by the rule engine.
*   **Analysis**: Evaluates intent, payload semantics, and potential for logic abuse.
*   **Latency**: Seconds (optimized to only run on `SUSPICIOUS` verdicts).

### 3. Risk Scoring & Decision Engine
*   **Purpose**: Synthesize inputs to determine the request's fate.
*   **Logic**: Aggregates Rule Score + LLM Score + Behavioral Score.
*   **Decisions**:
    *   **ALLOW**: Forward to `Real Backend`.
    *   **MONITOR**: Log but forward (Low Risk).
    *   **THROTTLE**: Artificial delay (Medium Risk / Brute Force).
    *   **DECEIVE**: Route to `Honeypot Environment` (High Risk).

### 4. Deception & Honeypot Logic
*   **Function**: Simulates a vulnerable version of the target service.
*   **Mechanism**:
    *   **Generation**: AI generates a realistic "failure" or "success" response (e.g., specific SQL error).
    *   **Caching**: Responses are cached by `Signature` (Path + Query + Attack Type) to ensure **Consistency**. If an attacker repeats the same attack, they get the exact same "fake" response, maintaining the illusion.
*   **Goal**: Maximize time-on-target for the attacker while logging all interaction data.

### 5. Behavioral Analysis
*   **Purpose**: Detect anomalies over time rather than per-request.
*   **Mechanism**: Tracks request rates per IP and login failure patterns.
*   **Action**: Increases Risk Score dynamically if an IP exceeds thresholds (e.g., Brute Force).

## Request Pipeline (Canonical Flow)
The gateway follows a strict 8-step pipeline for every request:

1.  **Normalization**: Decode and unquote payload.
2.  **Rule Check**: Regex evaluation.
3.  **LLM Check**: Conditional semantic analysis.
4.  **Risk Calculation**: `Rule + LLM`.
5.  **Behavior Check**: `+ Behavioral Score`.
6.  **Decision**: `Monitor`, `Throttle`, `Deceive`.
7.  **Deception**: If `DECEIVE`, return fake response (Stop).
8.  **Forwarding**: Else, forward to backend.

## Shadow Monitoring
To minimize impact on legitimate users, the system employs **Shadow Monitoring** for ambiguous cases. Traffic is logged extensively (`MONITOR` mode) while being allowed to access the backend, ensuring availability is prioritized over strict blocking.
