# AI-Honeypot-Gateway

> An intelligent, adaptive reverse proxy that intercepts, analyzes, and neutralizes cyber threats using a multi-layer detection engine powered by rule-based logic and local LLM analysis.

## Problem Statement
Traditional Intrusion Detection Systems (IDS) and Web Application Firewalls (WAF) often rely on static signatures, making them rigid and prone to false positives or evasion by novel attacks. They typically block traffic immediately, missing the opportunity to gather intelligence on attacker behavior and intent.

This system bridges the gap by acting as a smart gateway in front of vulnerable applications. Instead of simply blocking requests, it employs a decision engine that can route suspicious traffic to a high-fidelity deceptive honeypot. This allows for real-time analysis, threat attribution, and the collection of valuable forensic data without exposing the actual backend services.

## Key Features: 5-Layer Defense
The gateway employs a "Defense in Depth" strategy:

1.  **Request Logging**: Captures full request details (Path, Query, Body, Headers) in SQLite.
2.  **Rule Engine**: Regex-based filtering for known attacks (SQLi, XSS, SSRF, LFI, XXE, Web Shells).
3.  **LLM Advisory**: Local AI (`phi3` via Ollama) semantically analyzes suspicious payloads.
4.  **Risk Scoring**: Quantifies threat level based on rules, LLM verdicts, and behavioral signals.
5.  **Behavioral Analysis**: Detects high-rate attacks and brute-force login attempts.

**+ Deception Engine**: If a threat is confirmed, the gateway seamlessly switches to "Deception Mode," returning fake but realistic responses (cached for consistency) to keep the attacker engaged.

## High-Level Architecture
The system operates as a reverse proxy gateway sitting between the external internet and the protected backend services.

1.  **Gateway Layer**: Intercepts all incoming HTTP/S traffic.
2.  **Analysis Pipeline**: Normalization -> Rule Check -> LLM Check -> Behavior Check.
3.  **Decision Engine**: Determines `ALLOW`, `MONITOR`, `THROTTLE`, or `DECEIVE`.
4.  **Honeypot Subsystem**: Generates and caches AI-driven fake responses.

## Installation

### Prerequisites
*   Python 3.9+
*   [Ollama](https://ollama.com/) running locally with `phi3` model (`ollama run phi3`).

### Setup
1.  Clone the repository:
    ```bash
    git clone https://github.com/waqar741/AI-Based-Honeypot.git
    cd AI-Honeypot-Gateway
    ```
2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

### 1. Start the Gateway
Run the FastAPI server on port 8000:
```bash
python -m uvicorn src.main:app --host 127.0.0.1 --port 8000 --reload
```

### 2. Start a Mock Backend (Optional)
If you don't have a real application to protect, run a simple Python HTTP server on port 9000:
```bash
python -m http.server 9000
```
*(The gateway forwards "Safe" traffic to `http://localhost:9000` by default)*

### 3. Access the Dashboard
View real-time attack logs and decision metrics:
*   URL: [http://localhost:8000/dashboard](http://localhost:8000/dashboard)

## Project Structure
*   `src/`: Source code for Gateway, Rules, AI, and Deception logic.
*   `docs/`: Detailed architecture and design documentation.
*   `tests/`: Verification scripts for all layers.
*   `data/`: SQLite database storage.

## Tool-Based Nature
This project is designed as a generic, reusable security tool, not a hardcoded solution for a specific application. It can be deployed in front of *any* web application (FastAPI, Flask, Node.js, etc.) by configuring the target backend URL.
