import re
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
from routers.hash_router import router as hash_router
from dashboard.router import router as dashboard_router
from routers.domain_router import router as domain_router
from routers.url_router import router as url_router
from routers.ip_router import router as ip_router
from routers.mail_router import router as mail_router
from routers.cve_router import router as cve_router
from routers.ioc_router import router as ioc_router
from routers.chatbot_router import router as chatbot_router
from routers.cve_router import router as cve_router
from database.db import init_db 


app = FastAPI(
    title="Threat Intelligence Platform",
    description="Plateforme TI pour enrichissement de hash, domaines, IP, URLs et emails",
    version="1.0"
)


init_db()

# Routers
app.include_router(hash_router, prefix="/hash", tags=["Hash Enrichment"])
app.include_router(domain_router, prefix="/domain", tags=["Domain Enrichment"])
app.include_router(ip_router, prefix="/ip", tags=["IP Reputation"])
app.include_router(url_router, prefix="/url", tags=["URL Reputation"])
app.include_router(dashboard_router, prefix="/dashboard", tags=["Dashboard"])
app.include_router(mail_router, prefix="/mail", tags=["Mail Reputation"])
app.include_router(cve_router, prefix="/cve", tags=["CVE Lookup"])
app.include_router(ioc_router, prefix="/ioc", tags=["IOC Analysis"])
app.include_router(chatbot_router, prefix="/chatbot", tags=["Chatbot"])

# Health check
@app.get("/", tags=["Health"])
def root():
    return {"status": "ok", "message": "Threat Intelligence Platform is running"}

