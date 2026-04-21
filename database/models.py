from sqlalchemy import Column, Integer, String, JSON, DateTime
from sqlalchemy.sql import func
from .db import Base


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, index=True)
    value = Column(String(255), index=True)
    type = Column(String(50), index=True)
    risk_level = Column(String(50))
    risk_score = Column(Integer)
    confidence = Column(String(50))
    source = Column(String(255))
    data = Column(JSON)
    created_at = Column(DateTime, server_default=func.now())


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    indicator = Column(String(255), index=True)
    risk_level = Column(String(50))
    risk_score = Column(Integer)
    confidence = Column(String(50))
    source = Column(String(255))
    created_at = Column(DateTime, server_default=func.now())


class IPReputation(Base):
    __tablename__ = "ip_reputation"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String(50), index=True)
    final_verdict = Column(String(50))
    country = Column(String(50))
    data = Column(JSON)
    created_at = Column(DateTime, server_default=func.now())
