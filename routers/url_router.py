from fastapi import APIRouter, Query
from services.url_service import get_url_report

router = APIRouter()

@router.get("/")
def url_lookup(param: str = Query(..., description="URL to scan")):
    return get_url_report(param)