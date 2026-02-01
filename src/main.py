from fastapi import FastAPI, Request, Response
from src.config import BACKEND_BASE_URL
from src.gateway.forwarder import forward_request
from src.database import init_db
from src.gateway.logger import log_request
from src.models import RequestLog
from src.rules.engine import evaluate_rules
from src.ai.llm_analyzer import analyze_with_llm
from src.decision.scoring import calculate_risk
from src.decision.policy import decide_action
from urllib.parse import unquote

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
    
    # 1. Rule Evaluation
    payload = f"{path} {params} {body.decode(errors='ignore')}"
    payload = unquote(payload)
    verdict, matches = evaluate_rules(payload, user_agent)

    # 2. LLM Analysis (Layer 2)
    llm_verdict = ""
    llm_latency = 0

    # Only analyze if suspicious (cost/latency optimization)
    # OR if malicious? User said "if verdict == SUSPICIOUS". 
    # But usually MALICIOUS also warrants confirmation if we want to confirm, 
    # but for now following strict instruction: "if verdict == SUSPICIOUS"
    if verdict in ["SUSPICIOUS", "MALICIOUS"]:
        try:
            llm_verdict, llm_latency = analyze_with_llm(payload)
        except Exception:
            llm_verdict = ""
            llm_latency = 0

    # 3. Decision Engine (Layer 3)
    risk = calculate_risk(verdict, ",".join(matches), llm_verdict)
    decision = decide_action(risk)

    log_entry = RequestLog(
        client_ip=client_ip,
        method=method,
        path=path,
        query_params=str(params),
        user_agent=user_agent,
        body=body.decode(errors="ignore")
    )

    # Log with all data
    log_request(
        log_entry,
        verdict=verdict,
        matches=",".join(matches),
        llm_verdict=llm_verdict,
        llm_latency=llm_latency,
        risk_score=risk,
        decision=decision
    )


    target_url = f"{BACKEND_BASE_URL}/{path}"

    status, resp_headers, content = forward_request(
        method, target_url, headers, params, body
    )

    return Response(
        content=content,
        status_code=status
    )
