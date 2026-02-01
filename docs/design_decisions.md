# Design Decisions

## 1. Why FastAPI?
*   **Performance**: Built on Starlette and Pydantic, it offers high performance (async/await) crucial for a proxy gateway adding minimal latency.
*   **Concurrency**: Native async support allows efficient handling of multiple concurrent connections.
*   **Type Safety**: Robust data validation prevents many classes of injection attacks on the gateway itself.

## 2. Why SQLite?
*   **Simplicity**: Deployment is zero-conf (no separate DB server), reducing complexity for users.
*   **Portability**: The database is a single file, easily backed up or moved for offline analysis.
*   **Sufficiency**: For a single-node gateway/honeypot instance, SQLite's write throughput is adequate for attack logging.

## 3. Why Local LLM (e.g., Ollama)?
*   **Privacy**: Sensitive traffic data is never sent to a third-party API.
*   **Cost**: No per-token usage fees.
*   **Latency**: Eliminates network round-trips to external AI services.
*   **Control**: Allows fine-tuning the model for security logs without API restrictions.

## 4. Why Deception > Blocking?
*   **Intelligence**: Deception keeps the attacker unaware they are detected.
*   **Resource Wasting**: Engages the attacker in a fake environment, wasting their time.
*   **Attribution**: Longer engagement sessions provide more forensic data (IPs, tools, behavior).

## 5. Gateway Architecture
*   **Agnostic Protection**: Protects any backend (FastAPI, Flask, Node.js) without code changes.
*   **Isolation**: If the deception layer is compromised, the real backend remains safe.

## 6. Logic Encapsulation (SecurityFilter Class)
*   **Why Class-based?**: We moved from global regex lists to a `SecurityFilter` class to encapsulate distinct pattern matching methods (`check_input`, `check_hpp`). This improves maintainability and allows stateful checks if needed in the future.

## 7. Behavioral Analysis Layer
*   **Why needed?**: Static rules miss "slow and low" attacks or valid credentials being brute-forced.
*   **Mechanism**: We track rate limits and login failures *per IP*. This adds a dynamic risk score that static regex cannot provide.

## 8. Strict 8-Step Pipeline
*   **Why?**: To ensure deterministic processing. Every request MUST go through:
    `Normalize -> Rule -> LLM -> Risk -> Behavior -> Decision -> Deception -> Forward`.
    This prevents "fail-open" scenarios where a check might be skipped accidentally.
