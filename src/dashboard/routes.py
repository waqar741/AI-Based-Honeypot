from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates
from src.dashboard.queries import fetch_recent_logs

from pathlib import Path

router = APIRouter()
base_dir = Path(__file__).resolve().parent.parent.parent
templates_dir = base_dir / "templates"
templates = Jinja2Templates(directory=str(templates_dir))

@router.get("/dashboard")
def dashboard(request: Request):
    logs = fetch_recent_logs()
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "logs": logs}
    )
