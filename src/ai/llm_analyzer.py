import requests
import time

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "phi3"  # or llama3.2

CLASSIFICATION_PROMPT = """
You are a web security analysis assistant.

Classify the following HTTP request content as either:
SAFE
or
UNSAFE

Rules:
- Respond with ONLY one word: SAFE or UNSAFE
- Do not explain
- Consider SQL injection, XSS, path traversal, command injection

Request Content:
{payload}
"""

def analyze_with_llm(payload: str):
    prompt = CLASSIFICATION_PROMPT.format(payload=payload)

    start = time.time()
    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL_NAME,
                "prompt": prompt,
                "stream": False
            },
            timeout=30
        )
        latency_ms = int((time.time() - start) * 1000)

        if response.status_code != 200:
            return "UNKNOWN", latency_ms

        text = response.json().get("response", "").strip().upper()

        if "SAFE" in text: # flexible matching in case of extra chars
             if "UNSAFE" not in text: # prioritize UNSAFE if ambiguous
                 return "SAFE", latency_ms
        
        if "UNSAFE" in text:
            return "UNSAFE", latency_ms
            
        # strict fallback from requirements:
        if text == "SAFE":
             return "SAFE", latency_ms
        if text == "UNSAFE":
             return "UNSAFE", latency_ms
             
        return "UNKNOWN", latency_ms
        
    except Exception as e:
        latency_ms = int((time.time() - start) * 1000)
        return "ERROR", latency_ms
