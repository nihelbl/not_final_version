from fastapi import APIRouter, Query, HTTPException
from services.ip_service import check_ip_reputation
import ipaddress
from sqlalchemy.orm import Session
from fastapi import Depends
from database.db import get_db
from database.models import IPReputation

router = APIRouter()

@router.get("/", summary="IP Reputation Check")
def ip_route(
    param: str = Query(..., description="IPv4 or IPv6 address"),
    db: Session = Depends(get_db)
):
    # Validate IP
    try:
        ipaddress.ip_address(param)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    result = check_ip_reputation(param)
    new_ip = IPReputation(
        ip=param,
        final_verdict=result.get("final_verdict"),
        country=result.get("virustotal", {}).get("country"),
        data=result
    )

    db.add(new_ip)
    db.commit()

    return result