import httpx
import base64
import asyncio
import os
from urllib.parse import urlparse
from dotenv import load_dotenv

# Load the variables from the .env file
load_dotenv()

# Pull the keys into your application
VT_API_KEY = os.getenv("VT_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")

# Add a failsafe warning if keys are missing
if not VT_API_KEY or not OTX_API_KEY:
    print("WARNING: API Keys are missing. URL Scanner will fail.")

def extract_domain(url: str) -> str:
    """Extracts the base domain from a URL for OTX querying."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return urlparse(url).netloc.split(':')[0]

async def fetch_virustotal(client: httpx.AsyncClient, target_url: str) -> dict:
    """Asynchronously queries the VirusTotal v3 API."""
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    
    try:
        response = await client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=10.0)
        
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return {"status": "completed", "stats": stats}
        elif response.status_code == 404:
            # If VT hasn't seen it, submit it for a new scan
            await client.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": target_url}, timeout=10.0)
            return {"status": "queued", "message": "New URL submitted to VT for analysis."}
        else:
            return {"status": "error", "message": f"VT API Error {response.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

async def fetch_alienvault(client: httpx.AsyncClient, target_url: str) -> dict:
    """Asynchronously queries AlienVault OTX for threat pulses linked to the domain."""
    domain = extract_domain(target_url)
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    
    try:
        response = await client.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general", headers=headers, timeout=10.0)
        
        if response.status_code == 200:
            data = response.json()
            pulse_count = data.get('pulse_info', {}).get('count', 0)
            # Grab the names of the top 3 most recent threat campaigns (pulses)
            recent_pulses = [p['name'] for p in data.get('pulse_info', {}).get('pulses', [])[:3]]
            
            return {
                "status": "completed", 
                "domain": domain,
                "pulse_count": pulse_count, 
                "recent_pulses": recent_pulses
            }
        elif response.status_code == 404:
            return {"status": "completed", "domain": domain, "pulse_count": 0, "recent_pulses": []}
        else:
            return {"status": "error", "message": f"OTX Error {response.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

async def async_scan_url_combined(target_url: str) -> dict:
    """Fires both API requests concurrently and merges the results."""
    async with httpx.AsyncClient() as client:
        # Create the tasks
        vt_task = fetch_virustotal(client, target_url)
        otx_task = fetch_alienvault(client, target_url)
        
        # Execute both simultaneously without blocking
        vt_result, otx_result = await asyncio.gather(vt_task, otx_task)
        
        return {
            "target": target_url,
            "virustotal": vt_result,
            "alienvault": otx_result
        }

