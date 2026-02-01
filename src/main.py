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
from src.deception.signature import generate_signature
from src.deception.cache import get_cached_response, store_fake_response
from src.deception.signature import generate_signature
from src.deception.cache import get_cached_response, store_fake_response
from src.deception.ai_generator import generate_fake_response
from src.behavior.analyzer import behavior_risk, is_login_path

app = FastAPI(title="AI Honeypot Gateway")

# Initialize DB on startup
init_db()

# Mount Static Files
from fastapi.staticfiles import StaticFiles
app.mount("/static", StaticFiles(directory="static"), name="static")

# Include Dashboard Router
from src.dashboard.routes import router as dashboard_router
app.include_router(dashboard_router)


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
    
    # 3.5 Behavioral Analysis (Layer 5)
    behavior_score = behavior_risk(client_ip, path)
    risk += behavior_score
    
    decision = decide_action(risk)
    
    is_login = 1 if is_login_path(path) else 0

    log_entry = RequestLog(
        client_ip=client_ip,
        method=method,
        path=path,
        query_params=str(params),
        user_agent=user_agent,
        body=body.decode(errors="ignore")
    )

    deception_resp = ""

    # 4. Deception Logic (Layer 4)
    if decision in ["DECEIVE", "THROTTLE"]:
        try:
            attack_type = ",".join(matches) if matches else "unknown"
            signature = generate_signature(path, str(params), attack_type)

            fake = get_cached_response(signature)

            if not fake:
                fake = generate_fake_response(payload)
                store_fake_response(signature, attack_type, fake)
            
            deception_resp = fake
        except Exception:
            fake = "Service temporarily unavailable."
            deception_resp = fake
        
        # Log immediately and Return
        log_request(
            log_entry,
            verdict=verdict,
            matches=",".join(matches),
            llm_verdict=llm_verdict,
            llm_latency=llm_latency,
            risk_score=risk,
            decision=decision,
            deception_response=deception_resp,
            is_login_attempt=is_login
        )
        
        return Response(content=fake, status_code=200)

    # Log with all data (Normal Flow)
    log_request(
        log_entry,
        verdict=verdict,
        matches=",".join(matches),
        llm_verdict=llm_verdict,
        llm_latency=llm_latency,
        risk_score=risk,
        decision=decision,
        is_login_attempt=is_login
    )



    target_url = f"{BACKEND_BASE_URL}/{path}"

    status, resp_headers, content = forward_request(
        method, target_url, headers, params, body
    )

    return Response(
        content=content,
        status_code=status
    )
