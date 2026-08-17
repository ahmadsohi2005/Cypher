import httpx
import asyncio
from datetime import datetime
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import os

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# --- 1. UPGRADED EMAIL ANALYTICS ---
async def get_breach_analytics(email: str) -> dict:
    """Uses XposedOrNot to find exactly what data was leaked."""
    url = f"https://api.xposedornot.com/v1/breach-analytics?email={email}"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, timeout=10.0)
            if response.status_code == 200:
                data = response.json()
                metrics = data.get("BreachMetrics", {})
                return {"status": "success", "exposed_data": metrics.get("data_classes", [])}
            return {"status": "failed", "error": "No analytics found."}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

# --- 2. UPGRADED IP GEOLOCATION ---
async def get_ip_geolocation(ip: str) -> dict:
    """Uses IP-API with advanced fields to detect proxies and datacenters."""
    url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,proxy,hosting"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, timeout=10.0)
            data = response.json()
            if data.get("status") == "success":
                return {
                    "status": "success",
                    "country": data.get("country"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "asn": data.get("as"),
                    "is_proxy": data.get("proxy", False),
                    "is_hosting": data.get("hosting", False)
                }
            return {"status": "failed", "error": "Could not resolve location"}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

# --- 3. DOMAIN INFRASTRUCTURE (NEW) ---
async def get_domain_dns(domain: str) -> dict:
    """Uses Google Public DNS to extract raw infrastructure records."""
    url = f"https://dns.google/resolve?name={domain}&type=ANY"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, timeout=10.0)
            data = response.json()
            records = [ans["data"] for ans in data.get("Answer", [])]
            return {"status": "success", "records": records[:10]}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

async def get_domain_whois(domain: str) -> dict:
    """Uses RDAP for registration dates."""
    url = f"https://rdap.org/domain/{domain}"
    async with httpx.AsyncClient(follow_redirects=True) as client:
        try:
            response = await client.get(url, timeout=15.0)
            if response.status_code == 200:
                data = response.json()
                events = data.get("events", [])
                expiration = next((e["eventDate"] for e in events if e["eventAction"] == "expiration"), "Unknown")
                return {"status": "success", "expiration": expiration}
            return {"status": "failed", "error": "No RDAP data found."}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

# --- 4. WEB SCRAPER ---
async def scrape_website_metadata(domain: str) -> dict:
    """Scrapes the target domain for metadata, server headers, and basic info."""
    url = f"http://{domain}" if not domain.startswith("http") else domain
    async with httpx.AsyncClient(verify=False) as client:
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            response = await client.get(url, headers=headers, follow_redirects=True, timeout=15.0)
            
            soup = BeautifulSoup(response.text, 'html.parser')
            title = soup.title.string if soup.title else "No Title Found"
            
            meta_desc = soup.find("meta", attrs={"name": "description"})
            description = meta_desc["content"] if meta_desc else "No description found"
            
            server_header = response.headers.get("Server", "Hidden/Unknown")
            
            return {
                "status": "success", 
                "title": title.strip(), 
                "description": description.strip(),
                "server": server_header
            }
        except Exception as e:
            return {"status": "failed", "error": str(e)}

# --- EXISTING OSINT FUNCTIONS ---
async def check_abuseipdb(ip_address: str) -> dict:
    if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY == "YOUR_ABUSEIPDB_KEY_HERE":
        return {"status": "failed", "error": "Missing API Key"}
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, params={"ipAddress": ip_address, "maxAgeInDays": "90"}, timeout=10.0)
            if response.status_code == 200:
                data = response.json().get("data", {})
                return {"status": "success", "abuse_score": data.get("abuseConfidenceScore", 0), "total_reports": data.get("totalReports", 0)}
            return {"status": "failed", "error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

async def check_threatfox(target: str) -> dict:
    url = "https://threatfox-api.abuse.ch/api/v1/"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(url, json={"query": "search_ioc", "search_term": target}, timeout=10.0)
            data = response.json()
            if data.get("query_status") == "ok":
                return {"status": "success", "malware_hits": len(data.get("data", []))}
            return {"status": "safe", "malware_hits": 0}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

async def enumerate_subdomains(domain: str) -> dict:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, timeout=15.0)
            if response.status_code == 200:
                data = response.json()
                clean_subs = [sub for sub in list(set([entry["name_value"].lower() for entry in data])) if "*" not in sub][:20]
                return {"status": "success", "count": len(clean_subs), "subdomains": clean_subs}
            return {"status": "failed"}
        except:
            return {"status": "failed"}

async def get_archived_endpoints(domain: str) -> dict:
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&collapse=urlkey&output=json&limit=15"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, timeout=15.0)
            if response.status_code == 200:
                data = response.json()
                urls = [row[2] for row in data[1:]] if len(data) > 1 else []
                return {"status": "success", "count": len(urls), "urls": urls}
            return {"status": "failed"}
        except:
            return {"status": "failed"}

# --- AUTOMATED THREAT BRIEFING ---
def generate_markdown_report(target: str, data: dict, target_type: str) -> str:
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    report = f"# OSINT Threat Briefing: {target}\n**Generated:** {timestamp}\n\n"
    
    if target_type == "email":
        breach = data.get("breaches", {})
        report += "## Email Analytics\n"
        exposed_data = breach.get("exposed_data", [])
        if exposed_data:
            report += f"**CRITICAL:** Data exposed in leaks.\n"
            report += f"**Exposed Data Classes:** {', '.join(exposed_data)}\n"
        else:
            report += "**SAFE:** No known public data breaches found.\n"
            
    elif target_type == "ip":
        geo = data.get("geolocation", {})
        report += "## IP Infrastructure\n"
        report += f"- **Location:** {geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}\n"
        report += f"- **ISP/Org:** {geo.get('isp', 'Unknown')} (ASN: {geo.get('asn', 'Unknown')})\n"
        report += f"- **VPN/Proxy Detected:** {'YES' if geo.get('is_proxy') else 'NO'}\n"
        report += f"- **Datacenter Hosting:** {'YES' if geo.get('is_hosting') else 'NO'}\n"
        
    elif target_type == "domain":
        scraper = data.get("scraper", {})
        whois = data.get("whois", {})
        dns = data.get("dns", {})
        
        report += "## Infrastructure Recon\n"
        report += f"- **Expiration Date:** {whois.get('expiration', 'Unknown')}\n"
        report += f"- **Page Title:** {scraper.get('title', 'N/A')}\n"
        report += f"- **Server Tech:** {scraper.get('server', 'N/A')}\n"
        
        if dns.get("records"):
            report += "\n## Public DNS Records\n"
            for rec in dns.get("records", []):
                report += f"- {rec}\n"
        
    return report

# --- MASTER ORCHESTRATOR ---
async def run_osint_scan(target: str, target_type: str) -> dict:
    results = {}
    tasks = []
    
    if target_type == "email":
        # Fixed function call
        results["breaches"] = await get_breach_analytics(target)
        
    elif target_type == "ip":
        tasks = [check_threatfox(target), check_abuseipdb(target), get_ip_geolocation(target)]
        gathered = await asyncio.gather(*tasks)
        results["threatfox"], results["abuseipdb"], results["geolocation"] = gathered
        
    elif target_type == "domain":
        # Added new DNS and WHOIS functions to the task runner
        tasks = [
            check_threatfox(target), 
            enumerate_subdomains(target), 
            get_archived_endpoints(target), 
            scrape_website_metadata(target),
            get_domain_dns(target),
            get_domain_whois(target)
        ]
        gathered = await asyncio.gather(*tasks)
        results["threatfox"], results["subdomains"], results["archived_urls"], results["scraper"], results["dns"], results["whois"] = gathered
        
    results["markdown_report"] = generate_markdown_report(target, results, target_type)
    return results