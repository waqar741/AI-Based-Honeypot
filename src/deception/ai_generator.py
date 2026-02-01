import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "phi3"  # or llama3.2

PROMPT = """
You are simulating a buggy, insecure web application.

Generate a realistic but incorrect application response for the following request.
- Do NOT mention security, AI, or honeypots.
- Do NOT confirm success.
- The response should look plausible but not useful.

Request:
{payload}
"""

def generate_fake_response(payload):
    try:
        r = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "prompt": PROMPT.format(payload=payload),
                "stream": False
            },
            timeout=30 # Increased timeout for generation
        )

        if r.status_code != 200:
            return "Service temporarily unavailable."

        return r.json().get("response", "").strip()[:500]
    except Exception:
        return "Internal Server Error"
