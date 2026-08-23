import base64
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from app.services import log_analyzer
from app.core.auth import get_current_user

router = APIRouter(
    prefix="/api/logs",
    tags=["Log Analyzer"],
    dependencies=[Depends(get_current_user)]
)

class LogRequest(BaseModel):
    raw_logs: str
    is_encoded: bool = False  # Flag to allow WAF bypass

@router.post("/analyze")
async def analyze_logs(req: LogRequest):
    if not req.raw_logs.strip():
        raise HTTPException(status_code=400, detail="Log content cannot be empty.")
    
    # Decode the payload if the frontend encoded it to bypass cloud firewalls
    try:
        log_content = base64.b64decode(req.raw_logs).decode('utf-8', errors='ignore') if req.is_encoded else req.raw_logs
    except Exception:
        raise HTTPException(status_code=400, detail="Failed to decode log payload.")

    if len(log_content) > 40_000_000:
        raise HTTPException(status_code=400, detail="Log size exceeds 40MB limit.")
    
    return log_analyzer.parse_and_analyze_logs(log_content)
