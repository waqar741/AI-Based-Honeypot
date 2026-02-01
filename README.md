# AI-Honeypot-Gateway

> An intelligent, adaptive reverse proxy that intercepts, analyzes, and neutralizes cyber threats using a multi-layer detection engine powered by rule-based logic and local LLM analysis.

## Problem Statement
Traditional Intrusion Detection Systems (IDS) and Web Application Firewalls (WAF) often rely on static signatures, making them rigid and prone to false positives or evasion by novel attacks. They typically block traffic immediately, missing the opportunity to gather intelligence on attacker behavior and intent.

This system bridges the gap by acting as a smart gateway in front of vulnerable applications. Instead of simply blocking requests, it employs a decision engine that can route suspicious traffic to a high-fidelity deceptive honeypot. This allows for real-time analysis, threat attribution, and the collection of valuable forensic data without exposing the actual backend services.

## High-Level Architecture
The system operates as a reverse proxy gateway sitting between the external internet and the protected backend services.

1.  **Gateway Layer**: Intercepts all incoming HTTP/S traffic.
2.  **Analysis Engine**: A multi-stage pipeline that evaluates requests:
    *   **Rule-Based Filter**: Fast, regex-based signatures for known threats (SQLi, XSS).
    *   **AI/LLM Analyzer**: A local Large Language Model examines semantic context and obfuscated payloads.
3.  **Decision Engine**: Determines the action based on a threat score:
    *   **Allow**: Forward to the real backend.
    *   **Block**: Drop the request (for low-value noise).
    *   **Deceive**: Route to the Honeypot subsystem.
4.  **Honeypot Subsystem**: A mimicked backend that simulates successful exploitation to keep attackers engaged and monitored.

## Tool-Based Nature
This project is designed as a generic, reusable security tool, not a hardcoded solution for a specific application. It can be deployed in front of *any* web application (FastAPI, Flask, Node.js, etc.) by configuring the target backend URL. Its modular design allows for easy integration of new detection rules, LLM prompts, and honeypot scenarios.
