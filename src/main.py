from fastapi import FastAPI, Request, Response
from src.config import BACKEND_BASE_URL
from src.gateway.forwarder import forward_request
from src.database import init_db
from src.gateway.logger import log_request
from src.models import RequestLog
from src.rules.engine import evaluate_rules

app = FastAPI(title="AI Honeypot Gateway")

# Initialize DB on startup
init_db()

@app.get("/health")
def health():
    return {"status": "gateway alive"}

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def gateway(path: str, request: Request):
    method = request.method
    headers = dict(request.headers)
    params = dict(request.query_params)
    body = await request.body()

    client_ip = request.client.host if request.client else "unknown"
    user_agent = headers.get("user-agent", "")
    
    # Classify Request
    payload = f"{path} {params} {body.decode(errors='ignore')}"
    verdict, matches = evaluate_rules(payload, user_agent)

    log_entry = RequestLog(
        client_ip=client_ip,
        method=method,
        path=path,
        query_params=str(params),
        user_agent=user_agent,
        body=body.decode(errors="ignore")
    )

    # Log with verdict
    log_request(
        log_entry,
        verdict=verdict,
        matches=",".join(matches)
    )

    target_url = f"{BACKEND_BASE_URL}/{path}"

    status, resp_headers, content = forward_request(
        method, target_url, headers, params, body
    )

    return Response(
        content=content,
        status_code=status
    )
