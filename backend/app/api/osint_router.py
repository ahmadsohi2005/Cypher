from fastapi import APIRouter
from pydantic import BaseModel
from app.services import osint_analyzer

router = APIRouter(prefix="/api/osint", tags=["OSINT"])

class OsintRequest(BaseModel):
    target: str
    target_type: str  # Must be "ip" or "domain", "email"

@router.post("/scan")
async def run_osint(req: OsintRequest):
    """
    Executes the Multi-Source Correlation and Pivot Engine.
    Requires target_type to be specified as 'ip' or 'domain'.
    """
    results = await osint_analyzer.run_osint_scan(req.target, req.target_type)
    return results