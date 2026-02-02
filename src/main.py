import requests
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from urllib.parse import unquote

from src.database import init_db, get_connection # Needed for bait logging
from src.gateway.logger import log_request
from src.models import RequestLog
from src.rules.engine import evaluate_rules
from src.ai.llm_analyzer import analyze_with_llm
from src.config import BACKEND_BASE_URL
from src.decision.scoring import calculate_risk
from src.decision.policy import decide_action
from src.deception.signature import generate_signature
from src.deception.cache import get_cached_response, store_fake_response
from src.deception.ai_generator import generate_fake_response
from src.behavior.analyzer import behavior_risk, is_login_path
from src.dashboard.routes import router as dashboard_router
from fastapi.templating import Jinja2Templates # Import here to configure

app = FastAPI(title="AI Honeypot Gateway")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # For dev; restrict in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize DB
init_db()

from pathlib import Path

# Mount Static
# Use absolute path relative to this file to allow running from any CWD
base_dir = Path(__file__).resolve().parent.parent
static_dir = base_dir / "static"
if not static_dir.exists():
    static_dir.mkdir(parents=True, exist_ok=True)
    
if not static_dir.exists():
    static_dir.mkdir(parents=True, exist_ok=True)
    
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Configure Templates with absolute path (if dashboard routes use it, they might need a global config or similar. 
# Assuming dashboard_router uses a text/plain response or standard templates. 
# If routes import 'templates' directly, this might not fix it without modifying dashboard/routes.py.
# Checking imports...)
# Actually, dashboard/routes.py likely initializes its own templates.
# Let's just fix the dashboard route logic if possible or ignore if it's separate.
# Re-reading logs: "jinja2.exceptions.TemplateNotFound: 'dashboard.html'"
# The dashboard router likely does: templates = Jinja2Templates(directory="templates")
# I should verify dashboard/routes.py.

# Dashboard
app.include_router(dashboard_router)

@app.get("/health")
def health():
    return {"status": "gateway alive"}

# 1. Helper: Backend Forwarder
def forward_to_backend(method, path, query, headers, body):
    # Strip /supabase prefix if present to match target structure
    final_path = path
    if final_path.startswith("/supabase"):
        final_path = final_path.replace("/supabase", "", 1)
        
    url = f"{BACKEND_BASE_URL}{final_path}"
    
    # Remove Host header to avoid 403 from Cloudflare/Supabase
    headers_clean = headers.copy()
    if "host" in headers_clean:
        del headers_clean["host"]
    if "content-length" in headers_clean:
        del headers_clean["content-length"] # Let requests calc this
    
    try:
        resp = requests.request(
            method=method,
            url=url,
            params=query,
            headers=headers_clean,
            data=body,
            timeout=10 # Increased timeout
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


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def gateway_handler(request: Request, path: str):
    
    # ===============================
    # 1. Extract & normalize payload
    # ===============================
    body = await request.body()
    body_str = body.decode(errors='ignore')
    # Normalize path usage: request.url.path has leading slash, path param might not.
    # Using path for logic, request.url.path for forwarding.
    
    # ===============================
    # 0. BAIT ROUTES (Do not forward to Supabase)
    # ===============================
    if path.startswith("api/admin") or path.startswith("api/debug") or path.startswith("upload"):
        # Log the interaction
        risks_score, risks = behavior_risk(request.client.host, path, body_str)
        if not risks: 
            risks = ["suspicious_probing"] # Default risk for accessing hidden bait pages

        # Prepare fake response content
        fake_content = "Action Logged."
        if "ping" in path:
            fake_content = "Pinging target... Request Timed Out."
        elif "sql" in path:
            fake_content = "Syntax Error: Unclosed quotation mark after the character string."
        elif "view-log" in path:
            fake_content = "[2024-02-01] CRITICAL: Root password rotation failed."
        elif "upload" in path:
            fake_content = "File uploaded to /var/www/uploads (Quarantined)."

        # Log using standard logger
        log_entry = RequestLog(
            client_ip=request.client.host if request.client else "unknown",
            method=request.method,
            path=path,
            query_params=str(request.query_params),
            user_agent=request.headers.get("user-agent", ""),
            body=body_str
        )

        log_request(
            log_entry,
            verdict="SUSPICIOUS",
            matches=",".join(risks),
            llm_verdict="",
            llm_latency=0,
            risk_score=90,
            decision="DECEIVE",
            deception_response=fake_content,
            is_login_attempt=0
        )
        
        return Response(content=fake_content, status_code=200, headers={"X-Honeypot-Trap": "true"})

    raw_payload = f"{path} {request.url.query} {body_str}"
    payload = unquote(raw_payload)

    client_ip = request.client.host if request.client else "unknown"
    header_dict = dict(request.headers)
    user_agent = header_dict.get("user-agent", "")

    # ===============================
    # 2a. Whitelist Check (Supabase/Trusted Paths)
    # ===============================
    SAFE_PREFIXES = ["supabase/", "rest/v1/", "auth/v1/"]
    if any(path.startswith(p) for p in SAFE_PREFIXES):
        # Skip analysis for trusted internal backend paths
        rule_verdict = "SAFE"
        matches = []
        llm_verdict = ""
        llm_latency = 0
        risk = 0
        decision = "ALLOW"
    else:
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
        if "api/admin" not in path and "api/debug" not in path: # Don't double count risks on known bait
             behavior_score, behavior_vectors = behavior_risk(client_ip, path, body.decode(errors='ignore'))
             risk += behavior_score
             if behavior_vectors:
                 matches.extend(behavior_vectors)

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
            media_type="text/plain",
            headers={"X-Honeypot-Trap": "true"}
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

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error": "Internal Server Error", "detail": str(exc)},
    )
