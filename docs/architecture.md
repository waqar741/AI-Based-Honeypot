# System Architecture

## Gateway Positioning
The AI-Honeypot-Gateway is positioned as a **Reverse Proxy** at the network edge, directly facing the internet. It acts as the primary entry point for all client traffic, abstracting the actual backend infrastructure. This "Man-in-the-Middle" position enables complete visibility and control over both incoming requests and outgoing responses.

## Multi-Layer Analysis Flow
The detection logic is built on a "Defense in Depth" strategy, processing requests through increasingly sophisticated layers:

### 1. Rule-Based Engine (Fast Path)
*   **Purpose**: Rapidly identify and filter obvious, high-volume automated attacks.
*   **Mechanism**: Uses compiled Regular Expressions (Regex) and pattern matching against HTTP headers, query parameters, and body content.
*   **Targets**: Known Scanner User-Agents, crude SQL injection signatures, basic XSS tags.
*   **Latency**: Microseconds.

### 2. LLM-Assisted Analysis (Slow Path)
*   **Purpose**: Detect complex, obfuscated, or context-specific attacks that evade static rules.
*   **Mechanism**: A local Large Language Model (LLM) analyzes suspicious requests identified (but not blocked) by the rule engine, or a random sample of traffic.
*   **Analysis**: Evaluates intent, payload semantics, and potential for logic abuse.
*   **Latency**: Milliseconds to Seconds (asynchronous or buffered).

### 3. Decision Engine
*   **Purpose**: Synthesize inputs from all layers to determine the request's fate.
*   **Logic**: Aggregates risk scores.
    *   **Clean Traffic**: Proxy to `Real Backend`.
    *   **Confirmed Threat**: Route to `Honeypot Environment`.
    *   **Ambiguous**: Route to `Honeypot` for further observation (Shadow Mode).

### 4. Deception & Honeypot Logic
*   **Location**: Independent module within the Gateway.
*   **Function**: Simulates a vulnerable version of the target service. It generates realistic error messages, fake data leaks, or successful "login" responses to keep the attacker engaged.
*   **Goal**: Maximize time-on-target for the attacker while logging all interaction data.

## Shadow Monitoring
To minimize impact on legitimate users, the system employs **Shadow Monitoring** for ambiguous cases. Traffic is duplicated: one stream goes to the real backend (if low risk) while the analysis engine processes the copy. If the analysis confirms a threat later, the IP is added to a block/deceive list for future requests, implementing a "detect now, block later" approach for complex scenarios.
