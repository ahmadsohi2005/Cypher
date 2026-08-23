from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
import asyncio

from app.services import scanner_utils
from app.services import url_analyzer
from app.core.auth import get_current_user

router = APIRouter(
    prefix="/api/scanner",
    tags=["Malicious URL Scanner"],
    dependencies=[Depends(get_current_user)]
)

class URLScanRequest(BaseModel):
    url: str

@router.post("/url")
async def scan_url(req: URLScanRequest):
    """Handles VirusTotal and AlienVault OTX checks."""
    if not req.url.startswith(("http://", "https://")):
        req.url = "http://" + req.url
    
    result = await scanner_utils.async_scan_url_combined(req.url)
    return result

@router.post("/advanced")
async def run_advanced_url_scan(req: URLScanRequest):
    """Handles Visual Capture, SSL Inspection, and Typosquatting checks."""
    if not req.url.startswith(("http://", "https://")):
        req.url = "http://" + req.url

    # Fire off the network-heavy tasks simultaneously
    ssl_task = url_analyzer.async_ssl_inspect(req.url)
    screenshot_task = url_analyzer.async_capture_screenshot(req.url)
    
    # The typosquatting check is pure math and fast enough to run instantly
    phishing_result = url_analyzer.check_typosquatting(req.url)
    
    # Wait for the network tasks to finish
    ssl_result, screenshot_result = await asyncio.gather(ssl_task, screenshot_task)
    
    return {
        "target": req.url,
        "phishing": phishing_result,
        "ssl": ssl_result,
        "visual_capture": screenshot_result
    }
