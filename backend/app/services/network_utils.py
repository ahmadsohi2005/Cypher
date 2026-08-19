import asyncio
import platform
import re
import subprocess
from urllib.parse import urlparse
import dns.resolver 
import ipaddress
import whois
from mac_vendor_lookup import AsyncMacLookup
import asyncio
import os
import httpx
from dotenv import load_dotenv
import requests
import concurrent.futures

load_dotenv()
MAC_API_KEY = os.getenv("MAC_API_KEY")

GLOBAL_SOCKET_LIMITER = asyncio.Semaphore(1000)

def sanitize_target(target: str) -> str:
    """Strips protocols and paths to return a clean hostname or IP."""
    target = target.strip()
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    return urlparse(target).netloc.split(':')[0]

def sanitize_subnet(base_ip: str) -> str:
    """Ensures the base IP is formatted correctly (e.g., 192.168.1.)"""
    parts = base_ip.strip('.').split('.')
    if len(parts) == 4:
        parts = parts[:3]
    return ".".join(parts) + "."
# PING
async def async_ping(host: str, count: int = 4) -> dict:
    clean_host = sanitize_target(host)
    
    def tcp_ping():
        import time, socket
        try:
            start_time = time.time()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((clean_host, 80)) # TCP ping on port 80
            rtt = round((time.time() - start_time) * 1000, 2)
            return {"host": clean_host, "status": "up", "rtt": f"{rtt} ms"}
        except Exception as e:
            return {"host": clean_host, "status": "down", "rtt": None, "error": str(e)}
            
    return await asyncio.to_thread(tcp_ping)
# PING SWEEP
async def async_ping_sweep(base_ip: str, start_range: int, end_range: int) -> list:
    clean_base = sanitize_subnet(base_ip)
    
    def check_host(ip):
        import socket
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((ip, 80)) # TCP connect instead of ICMP echo
            return {"host": ip, "status": "up"}
        except:
            return None

    def run_sweep():
        active = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            ips_to_test = [f"{clean_base}{i}" for i in range(start_range, end_range + 1)]
            results = executor.map(check_host, ips_to_test)
            for r in results:
                if r: active.append(r)
        return active

    return await asyncio.to_thread(run_sweep)
    # GRAB BANNER
async def grab_banner(reader, writer) -> str:
    try:
        writer.write(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), timeout=0.5)
        banner = data.decode('utf-8', errors='ignore').strip()
        return banner.split('\n')[0][:50] + "..." if len(banner) > 50 else banner
    except Exception:
        return "Open (No Banner)"

async def check_port_with_banner(ip: str, port: int) -> dict:
    async with GLOBAL_SOCKET_LIMITER:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=0.5
            )
            banner = await grab_banner(reader, writer)
            writer.close()
            await writer.wait_closed()
            return {"port": port, "status": "open", "banner": banner}
        except Exception:
            return {"port": port, "status": "closed"}
# PORT SCANNER
async def async_port_scan(target: str, ports: list) -> list:
    clean_host = sanitize_target(target)
    results = []
    chunk_size = 200 # Process in batches to prevent socket exhaustion
    
    for i in range(0, len(ports), chunk_size):
        chunk = ports[i:i+chunk_size]
        tasks = [check_port_with_banner(clean_host, port) for port in chunk]
        chunk_results = await asyncio.gather(*tasks)
        results.extend([res for res in chunk_results if res["status"] == "open"])
        
    return results
# TRACEROUTE
def sync_traceroute(host: str) -> list:
    is_win = platform.system().lower() == 'windows'
    # -h 10 restricts hops, -w 100 sets a fast 100ms timeout per hop
    cmd = ['tracert', '-d', '-h', '10', '-w', '100', host] if is_win else ['traceroute', '-n', '-m', '10', '-w', '1', host]
    
    try:
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        hops = [line.strip() for line in process.stdout.splitlines() if line.strip() and not line.startswith("Tracing")]
        return hops if hops else ["Traceroute failed to route path."]
    except subprocess.TimeoutExpired:
        return ["Traceroute timed out. The host may be dropping ICMP packets."]
    except Exception as e:
        return [f"Execution error: {str(e)}"]

async def async_traceroute(target: str) -> list:
    clean_host = sanitize_target(target)
    return await asyncio.to_thread(sync_traceroute, clean_host)
    # DNS LOOKUP
def sync_dns_lookup(domain: str) -> dict:
    """Synchronous DNS lookup designed to run safely in a thread."""
    clean_domain = sanitize_target(domain)
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
    results = {}
    
    for qtype in record_types:
        try:
            answer = resolver.resolve(clean_domain, qtype)
            results[qtype] = [rdata.to_text().strip('"') for rdata in answer]
        except Exception:
            results[qtype] = []
            
    return results

async def async_dns_lookup(domain: str) -> dict:
    """Offloads the DNS lookup to a background thread to prevent server freezing."""
    return await asyncio.to_thread(sync_dns_lookup, domain)
# WHOIS LOOKUP
def format_whois_date(date_obj):
    """Safely converts WHOIS datetime objects or arrays into YYYY-MM-DD strings."""
    if not date_obj:
        return "N/A"
    # WHOIS sometimes returns a list of dates; grab the first one
    if isinstance(date_obj, list):
        date_obj = date_obj[0]
    # If it's a valid datetime object, format it
    if hasattr(date_obj, "strftime"):
        return date_obj.strftime("%Y-%m-%d")
    # Fallback to standard string slicing
    return str(date_obj)[:10]

async def async_whois_lookup(domain: str) -> dict:
    """Fetches domain registrar and ownership information with clean dates."""
    clean_domain = sanitize_target(domain)
    
    def sync_whois():
        try:
            w = whois.whois(clean_domain)
            
            # Normalize emails and name servers into flat lists
            emails = w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else []
            name_servers = w.name_servers if isinstance(w.name_servers, list) else [w.name_servers] if w.name_servers else []
            
            return {
                "domain": w.domain_name,
                "registrar": w.registrar,
                "creation_date": format_whois_date(w.creation_date),
                "expiration_date": format_whois_date(w.expiration_date),
                "emails": [email for email in emails if email], # Clean out nulls
                "name_servers": [ns.lower() for ns in name_servers if ns]
            }
        except Exception as e:
            return {"error": f"WHOIS lookup failed: {str(e)}"}

    return await asyncio.to_thread(sync_whois)
# MAC LOOKUP
async def async_mac_lookup(mac_address: str) -> dict:
    """Identifies the hardware vendor using the macvendors.com API with Bearer auth."""
    url = f"https://api.macvendors.com/v1/lookup/{mac_address}"
    headers = {
        "Authorization": f"Bearer {MAC_API_KEY}",
        "Accept": "application/json"
    }
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, timeout=5.0)
            if response.status_code == 200:
                data = response.json()
                # Extract vendor from the standard macvendors v1 API response
                vendor = data.get("data", {}).get("organization_name", "Unknown Vendor")
                return {"mac": mac_address, "vendor": vendor, "status": "success"}
            elif response.status_code == 404:
                return {"mac": mac_address, "vendor": "MAC Not Found in Database", "status": "not_found"}
            else:
                return {"mac": mac_address, "vendor": f"API Error {response.status_code}", "status": "error"}
        except Exception as e:
            return {"mac": mac_address, "vendor": "Connection Timeout", "status": "error"}
# SUBNET CALCULATOR
def calculate_subnet(cidr: str) -> dict:
    """Translates CIDR notation into a detailed network profile. (Unchanged)"""
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
        return {
            "network_address": str(network.network_address),
            "broadcast_address": str(network.broadcast_address),
            "netmask": str(network.netmask),
            "total_hosts": network.num_addresses - 2 if network.num_addresses > 2 else network.num_addresses,
            "usable_range": f"{network.network_address + 1} - {network.broadcast_address - 1}" if network.num_addresses > 2 else "N/A",
            "status": "success"
        }
    except ValueError as e:
        return {"error": str(e), "status": "invalid_format"}
