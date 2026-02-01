from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates
from src.dashboard.queries import fetch_recent_logs

router = APIRouter()
templates = Jinja2Templates(directory="templates")

@router.get("/dashboard")
def dashboard(request: Request):
    logs = fetch_recent_logs()
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "logs": logs}
    )
