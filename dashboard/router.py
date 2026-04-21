from fastapi import APIRouter, Request, Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from services.hash_services import get_hash_report
from database.db import SessionLocal
from database.models import ScanHistory
from sqlalchemy import func

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])
templates = Jinja2Templates(directory="templates")

# ------------------------------
# Dashboard HTML avec stats
# ------------------------------
@router.get("/", response_class=HTMLResponse)
def dashboard_home(request: Request):
    db = SessionLocal()

    # Stats
    total_scans = db.query(ScanHistory).count()
    high = db.query(ScanHistory).filter(ScanHistory.risk_level == "High").count()
    medium = db.query(ScanHistory).filter(ScanHistory.risk_level == "Medium").count()
    low = db.query(ScanHistory).filter(ScanHistory.risk_level == "Low").count()
    by_source = db.query(ScanHistory.source, func.count(ScanHistory.id)).group_by(ScanHistory.source).all()

    # Historique
    scans = db.query(ScanHistory).order_by(ScanHistory.id.desc()).all()

    db.close()

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "total_scans": total_scans,
            "risk_levels": {"High": high, "Medium": medium, "Low": low},
            "by_source": dict(by_source),
            "scans": scans
        }
    )

# ------------------------------
# Scan hash depuis Dashboard
# ------------------------------
@router.post("/scan", response_class=HTMLResponse)
def dashboard_scan(request: Request, hash_value: str = Form(...)):
    result = get_hash_report(hash_value)

    if "error" in result:
        return templates.TemplateResponse(
            "dashboard.html",
            {"request": request, "error": "Hash not found"}
        )

    return templates.TemplateResponse(
        "result.html",
        {"request": request, "data": result}
    )
