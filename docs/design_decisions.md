# Design Decisions

## 1. Why FastAPI?
*   **Performance**: Built on Starlette and Pydantic, it offers high performance (async/await) crucial for a proxy gateway adding minimal latency.
*   **Concurrency**: Native support for asynchronous request processing allows handling multiple concurrent connections efficiently compared to blocking frameworks like specific Flask configurations.
*   **Type Safety**: Robust data validation prevents many classes of injection attacks on the gateway itself.

## 2. Why SQLite?
*   **Simplicity**: Deployment does not require a separate database server (like generic PostgreSQL/MySQL), reducing the "time-to-first-fix" for users.
*   **Portability**: The database is a single file, making it easy to backup, move, or analyze logs offline.
*   **Sufficiency**: For a single-node gateway/honeypot instance, SQLite's write throughput is sufficient for logging attack events.

## 3. Why Local LLM (e.g., Ollama/Llama)?
*   **Privacy**: Sensitive traffic data (potentially containing PII or passwords) is never sent to a third-party API (like OpenAI).
*   **Cost**: No per-token usage fees.
*   **Latency**: Eliminates network round-trips to external AI services, keeping decisions faster.
*   **Control**: Allows fine-tuning the model specific to security log analysis without API restrictions.

## 4. Why Deception > Blocking?
*   **Intelligence**: Blocking an attacker tells them they were detected, prompting them to change tactics. Deception keeps them completely unaware.
*   **Resource Wasting**: By engaging the attacker in a fake environment, we waste their time and resources that could be used against real targets.
*   **Attribution**: Longer engagement sessions provide more data (IPs, browser fingerprints, behavioral patterns) for identifying the threat actor.

## 5. Why Gateway Architecture?
*   **Agnostic Protection**: Can protect legacy apps, modern microservices, or static sites without requiring code changes in the backend application.
*   **Centralization**: Provides a single point of enforcement for security policies across multiple backend services.
*   **Isolation**: If the deception layer crashes or is compromised, the real backend remains isolated and untouched.
