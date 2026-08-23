import ssl
import socket
import asyncio
import base64
from datetime import datetime
from urllib.parse import urlparse
import tldextract
import Levenshtein
from playwright.sync_api import sync_playwright
import traceback

# Dictionary of commonly spoofed brands
HIGH_VALUE_TARGETS = [
    "google", "microsoft", "paypal", "apple", 
    "amazon", "facebook", "netflix", "bankofamerica", "icloud"
]

def extract_domain_name(url: str) -> str:
    """Uses the official Public Suffix List to perfectly extract the domain name."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
        
    extracted = tldextract.extract(url)
    return extracted.domain.lower()

# --- 1. PHISHING & TYPOSQUATTING ENGINE ---
def check_typosquatting(url: str) -> dict:
    domain_name = extract_domain_name(url)

    for target in HIGH_VALUE_TARGETS:
        if domain_name == target:
            return {"status": "safe", "message": f"Exact match for known brand: {target}"}

        # Check for Levenshtein distance OR if the target brand is hidden inside the string (e.g., br-icloud)
        distance = Levenshtein.distance(domain_name, target)

        if 0 < distance <= 2 or target in domain_name:
            return {
                "status": "malicious",
                "flagged_brand": target,
                "distance": distance if 0 < distance <= 2 else "Substring Match",
                "message": f"High probability of typosquatting. Imitating: {target}"
            }

    return {"status": "safe", "message": "No obvious typosquatting detected."}

# --- 2. SSL/TLS INSPECTOR ---
def sync_ssl_inspect(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.netloc or parsed.path

    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                organization = issuer_dict.get('organizationName', 'Unknown Issuer')

                expire_date_str = cert.get('notAfter')
                expire_date = datetime.strptime(expire_date_str, "%b %d %H:%M:%S %Y %Z")
                days_remaining = (expire_date - datetime.utcnow()).days

                return {
                    "status": "success",
                    "issuer": organization,
                    "days_remaining": days_remaining,
                    "expires": expire_date.strftime("%Y-%m-%d")
                }
    except socket.gaierror:
        # This catches the 11001 getaddrinfo error specifically
        return {"status": "failed", "error": "Domain is offline or sinkholed (DNS Resolution Failed)."}
    except Exception as e:
        return {"status": "failed", "error": f"SSL Handshake failed: {str(e)}"}

async def async_ssl_inspect(url: str) -> dict:
    """Wraps the blocking SSL check in a background thread."""
    return await asyncio.to_thread(sync_ssl_inspect, url)

# --- 3. SAFE VISUAL CAPTURE ---
def sync_capture_screenshot(url: str) -> dict:
    """Runs synchronously in a background thread to bypass Windows async loop bugs."""
    print(f"\n[DEBUG] 1. Starting threaded visual capture for: {url}")
    try:
        with sync_playwright() as p:
            print("[DEBUG] 2. Sync Playwright initialized. Launching Chromium...")
            browser = p.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-blink-features=AutomationControlled',
                    '--disable-infobars'
                ]
            )
            
            fake_user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            
            context = browser.new_context(
                ignore_https_errors=True,
                user_agent=fake_user_agent,
                viewport={'width': 1280, 'height': 720}
            )
            page = context.new_page()

            print("[DEBUG] 4. Page created. Navigating to URL...")
            try:
                page.goto(url, timeout=15000, wait_until='domcontentloaded')
                print("[DEBUG] 5. Navigation successful.")
                page.wait_for_timeout(2000)
            except Exception as nav_error:
                print(f"[DEBUG] 5b. Navigation timeout, forcing screenshot: {nav_error}")
                page.wait_for_timeout(2000)
            
            print("[DEBUG] 6. Taking screenshot...")
            screenshot_bytes = page.screenshot()
            b64_image = base64.b64encode(screenshot_bytes).decode('utf-8')

            print("[DEBUG] 7. Screenshot successful. Closing browser...")
            browser.close()
            return {"status": "success", "image_data": f"data:image/png;base64,{b64_image}"}
            
    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"\n[CRITICAL THREADED PLAYWRIGHT ERROR]\n{error_trace}\n")
        error_msg = str(e) if str(e).strip() else "Unknown internal crash in thread."
        return {"status": "failed", "error": error_msg}

async def async_capture_screenshot(url: str) -> dict:
    """Wraps the sync Playwright function in a background thread."""
    return await asyncio.to_thread(sync_capture_screenshot, url)
