import ssl
import socket
import asyncio
import base64
import urllib.parse
from datetime import datetime, timezone
from urllib.parse import urlparse
import tldextract
import Levenshtein
import httpx
import certifi
from cryptography import x509

# Try importing Playwright safely
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    sync_playwright = None

# Dictionary of commonly spoofed brands
HIGH_VALUE_TARGETS = [
    "google", "microsoft", "paypal", "apple", 
    "amazon", "facebook", "netflix", "bankofamerica", "icloud", "chase", "wellsfargo"
]

def extract_domain_name(url: str) -> str:
    """Uses the official Public Suffix List to extract the domain name."""
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
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    parsed = urlparse(url)
    hostname = parsed.netloc.split(':')[0] or parsed.path.split('/')[0]

    if not hostname:
        return {"status": "failed", "error": "Invalid target hostname."}

    # Step 1: Try standard handshake with trusted certifi CA bundle
    try:
        ctx = ssl.create_default_context(cafile=certifi.where())
        with socket.create_connection((hostname, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                organization = issuer_dict.get('organizationName', issuer_dict.get('commonName', 'Trusted CA'))

                expire_date_str = cert.get('notAfter')
                expire_date = datetime.strptime(expire_date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now_utc = datetime.now(timezone.utc)
                days_remaining = (expire_date - now_utc).days

                return {
                    "status": "success",
                    "issuer": organization,
                    "days_remaining": days_remaining,
                    "expires": expire_date.strftime("%Y-%m-%d")
                }
    except Exception:
        pass

    # Step 2: Resilient raw certificate parser using cryptography library (handles self-signed/expired/custom CA)
    try:
        cert_pem = ssl.get_server_certificate((hostname, 443), timeout=8)
        cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
        
        issuer_org = "Unknown Issuer"
        for attr in cert.issuer:
            if attr.oid == x509.oid.NameOID.ORGANIZATION_NAME or attr.oid == x509.oid.NameOID.COMMON_NAME:
                issuer_org = attr.value
                break

        expire_date = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=timezone.utc)
        now_utc = datetime.now(timezone.utc)
        days_remaining = (expire_date - now_utc).days

        return {
            "status": "success",
            "issuer": issuer_org,
            "days_remaining": days_remaining,
            "expires": expire_date.strftime("%Y-%m-%d")
        }
    except socket.timeout:
        return {"status": "failed", "error": "SSL inspection timed out. Port 443 unreachable."}
    except socket.gaierror:
        return {"status": "failed", "error": "Domain is offline or sinkholed (DNS Resolution Failed)."}
    except ConnectionRefusedError:
        return {"status": "failed", "error": "Port 443 connection refused (No SSL service active)."}
    except Exception as e:
        return {"status": "failed", "error": f"SSL inspection error: {str(e)}"}

async def async_ssl_inspect(url: str) -> dict:
    """Wraps SSL inspection in a background thread."""
    return await asyncio.to_thread(sync_ssl_inspect, url)

# --- 3. SAFE VISUAL CAPTURE ---
def sync_capture_screenshot_playwright(url: str) -> dict:
    """Attempts local headless Chromium screenshot if Playwright is present."""
    if not PLAYWRIGHT_AVAILABLE or sync_playwright is None:
        return {"status": "failed", "error": "Playwright not installed"}

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=[
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu',
                '--single-process',
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

        try:
            page.goto(url, timeout=10000, wait_until='domcontentloaded')
            page.wait_for_timeout(1000)
        except Exception:
            pass

        screenshot_bytes = page.screenshot()
        b64_image = base64.b64encode(screenshot_bytes).decode('utf-8')
        browser.close()
        return {"status": "success", "image_data": f"data:image/png;base64,{b64_image}"}

async def fetch_cloud_screenshot(url: str) -> dict:
    """Lightweight, resilient cloud fallback screenshot fetcher (works on Render free tier without Chromium)."""
    encoded_url = urllib.parse.quote(url, safe='')
    mshots_url = f"https://s0.wp.com/mshots/v1/{encoded_url}?w=1280&h=720"
    
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            resp = await client.get(mshots_url)
            if resp.status_code == 200 and len(resp.content) > 1000:
                b64_image = base64.b64encode(resp.content).decode('utf-8')
                content_type = resp.headers.get('content-type', 'image/jpeg')
                return {
                    "status": "success",
                    "image_data": f"data:{content_type};base64,{b64_image}"
                }
    except Exception as e:
        print(f"Cloud screenshot fallback error: {e}")
    
    return {"status": "failed", "error": "Visual capture unavailable for this domain."}

async def async_capture_screenshot(url: str) -> dict:
    """
    Executes screenshot capture:
    1. Tries local Playwright Chromium (if installed).
    2. Seamlessly falls back to fast cloud screenshot engine if Playwright is missing or fails.
    """
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    # Try local Playwright first if available
    if PLAYWRIGHT_AVAILABLE:
        try:
            res = await asyncio.to_thread(sync_capture_screenshot_playwright, url)
            if res.get("status") == "success":
                return res
        except Exception as e:
            print(f"Playwright capture notice: {e}. Switching to cloud fallback...")

    # Fallback to cloud screenshot provider
    return await fetch_cloud_screenshot(url)
