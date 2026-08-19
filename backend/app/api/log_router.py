from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.services import log_analyzer

router = APIRouter(prefix="/api/logs", tags=["Log Analyzer"])

class LogRequest(BaseModel):
    raw_logs: str

@router.post("/analyze")
async def analyze_logs(req: LogRequest):
    if not req.raw_logs.strip():
        raise HTTPException(status_code=400, detail="Log content cannot be empty.")
    if len(req.raw_logs) > 85_000_000:
        raise HTTPException(status_code=400, detail="Log size exceeds 85MB limit.")
    
    return log_analyzer.parse_and_analyze_logs(req.raw_logs)
