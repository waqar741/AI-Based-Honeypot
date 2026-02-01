import requests
from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles
from urllib.parse import unquote

from src.database import init_db
from src.gateway.logger import log_request
from src.models import RequestLog
from src.rules.engine import evaluate_rules
from src.ai.llm_analyzer import analyze_with_llm
from src.decision.scoring import calculate_risk
from src.decision.policy import decide_action
from src.deception.signature import generate_signature
from src.deception.cache import get_cached_response, store_fake_response
from src.deception.ai_generator import generate_fake_response
from src.behavior.analyzer import behavior_risk, is_login_path
from src.dashboard.routes import router as dashboard_router

app = FastAPI(title="AI Honeypot Gateway")

# Initialize DB
init_db()

# Mount Static
app.mount("/static", StaticFiles(directory="static"), name="static")

# Dashboard
app.include_router(dashboard_router)

@app.get("/health")
def health():
    return {"status": "gateway alive"}

# 1. Helper: Backend Forwarder
def forward_to_backend(method, path, query, headers, body):
    url = f"http://localhost:9000{path}"
    
    try:
        # Filter headers if necessary, but forwarding all for now
        resp = requests.request(
            method=method,
            url=url,
            params=query,
            headers=headers,
            data=body,
            timeout=5
        )
        return {
            "content": resp.content,
            "status": resp.status_code,
            "headers": dict(resp.headers)
        }
    except Exception as e:
        print(f"Backend connection error: {e}")
        return {
            "content": b"Bad Gateway",
            "status": 502,
            "headers": {}
        }


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def gateway_handler(request: Request, path: str):
    
    # ===============================
    # 1. Extract & normalize payload
    # ===============================
    body = await request.body()
    # Normalize path usage: request.url.path has leading slash, path param might not.
    # Using path for logic, request.url.path for forwarding.
    
    raw_payload = f"{path} {request.url.query} {body.decode(errors='ignore')}"
    payload = unquote(raw_payload)

    client_ip = request.client.host if request.client else "unknown"
    header_dict = dict(request.headers)
    user_agent = header_dict.get("user-agent", "")

    # ===============================
    # 2. Rule-based detection
    # ===============================
    # Ensure evaluate_rules returns strings/lists as expected
    rule_verdict, matches = evaluate_rules(payload, user_agent)

    # ===============================
    # 3. LLM advisory (optional)
    # ===============================
    llm_verdict = ""
    llm_latency = 0
    
    # "if rule_verdict == SUSPICIOUS" (Canonical requirement)
    if rule_verdict == "SUSPICIOUS":
        try:
            llm_verdict, llm_latency = analyze_with_llm(payload)
        except Exception:
            llm_verdict = ""
            llm_latency = 0

    # ===============================
    # 4. Risk scoring
    # ===============================
    risk = calculate_risk(rule_verdict, ",".join(matches), llm_verdict)

    # ===============================
    # 5. Behavioral escalation
    # ===============================
    risk += behavior_risk(client_ip, path)

    # ===============================
    # 6. Final decision
    # ===============================
    decision = decide_action(risk)
    
    is_login = 1 if is_login_path(path) else 0

    # Prepare Log Entry Object
    log_entry = RequestLog(
        client_ip=client_ip,
        method=request.method,
        path=path,
        query_params=str(request.query_params),
        user_agent=user_agent,
        body=body.decode(errors='ignore')
    )

    # ===============================
    # 7. DECEPTION PATH (FINAL)
    # ===============================
    if decision in ["DECEIVE", "THROTTLE"]:
        try:
            attack_type = ",".join(matches) if matches else "unknown"
            signature = generate_signature(path, str(request.query_params), attack_type)

            fake_resp = get_cached_response(signature)
            if not fake_resp:
                fake_resp = generate_fake_response(payload)
                store_fake_response(signature, attack_type, fake_resp)
        except Exception:
             fake_resp = "Service temporarily unavailable."

        log_request(
            log_entry,
            verdict=rule_verdict,
            matches=",".join(matches) if matches else "unknown",
            llm_verdict=llm_verdict,
            llm_latency=llm_latency,
            risk_score=risk,
            decision=decision,
            deception_response=fake_resp,
            is_login_attempt=is_login
        )

        return Response(
            content=fake_resp,
            status_code=200,
            media_type="text/plain"
        )

    # ===============================
    # 8. NORMAL FORWARDING PATH
    # ===============================
    forwarded = forward_to_backend(
        request.method, 
        request.url.path, 
        request.query_params, 
        header_dict, 
        body
    )

    log_request(
        log_entry,
        verdict=rule_verdict,
        matches=",".join(matches),
        llm_verdict=llm_verdict,
        llm_latency=llm_latency,
        risk_score=risk,
        decision=decision,
        is_login_attempt=is_login
    )

    return Response(
        content=forwarded["content"],
        status_code=forwarded["status"],
        # Exclude some headers to let FastAPI handle them (like Content-Length)
        # headers=forwarded["headers"] 
    )
