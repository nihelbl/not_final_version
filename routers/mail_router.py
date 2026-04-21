from fastapi import APIRouter, Query
from services.mail_service import check_mail_reputation

router = APIRouter()

@router.get("/", summary="Mail Reputation Check")
def mail_route(email: str = Query(..., description="Email to check")):
    return check_mail_reputation(email)