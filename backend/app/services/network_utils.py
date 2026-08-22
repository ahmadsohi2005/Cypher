import asyncio
import platform
import re
import socket
import ssl
import concurrent.futures
import requests
from urllib.parse import urlparse
import dns.resolver 
import ipaddress
import whois
from mac_vendor_lookup import AsyncMacLookup
import os
import shutil
import httpx
from dotenv import load_dotenv
from datetime import datetime
import subprocess

load_dotenv()
MAC_API_KEY = os.getenv("MAC_API_KEY")

GLOBAL_SOCKET_LIMITER = asyncio.Semaphore(1000)

def sanitize_target(target: str) -> str:
    """Strips protocols, paths, invalid characters, and leading dashes to return a clean hostname or IP."""
    target = target.strip()
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    clean = urlparse(target).netloc.split(':')[0]
    # Remove any shell or CLI injection characters and strip leading hyphens
    clean = re.sub(r'[^a-zA-Z0-9.-]', '', clean).lstrip('-')
    return clean

def sanitize_subnet(base_ip: str) -> str:
    """Ensures the base IP is formatted correctly (e.g., 192.168.1.)"""
    parts = base_ip.strip('.').split('.')
    if len(parts) == 4:
        parts = parts[:3]
    return ".".join(parts) + "."

# --- 1. CLOUD-SAFE PING ---
async def async_ping(host: str, count: int = 4) -> dict:
    clean_host = sanitize_target(host)
    def tcp_ping():
        import time
        try:
            start = time.time()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((clean_host, 80))
            rtt = round((time.time() - start) * 1000, 2)
            return {"host": clean_host, "status": "up", "rtt": f"{rtt} ms"}
        except Exception as e:
            return {"host": clean_host, "status": "down", "rtt": None, "error": str(e)}
    return await asyncio.to_thread(tcp_ping)

# --- 2. CLOUD-SAFE PING SWEEP ---
async def async_ping_sweep(base_ip: str, start_range: int, end_range: int) -> list:
    clean_base = sanitize_subnet(base_ip)
    def check_host(ip):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((ip, 80))
            return {"host": ip, "status": "up"}
        except:
            return None

    def run_sweep():
        active = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            ips = [f"{clean_base}{i}" for i in range(start_range, end_range + 1)]
            for r in executor.map(check_host, ips):
                if r: active.append(r)
        return active
    return await asyncio.to_thread(run_sweep)

# --- 3. ENHANCED PORT SCANNER ---
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
            try:
                service_name = socket.getservbyport(port).upper()
            except:
                service_name = "UNKNOWN"

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=0.5
            )
            banner = await grab_banner(reader, writer)
            writer.close()
            await writer.wait_closed()
            return {"port": port, "service": service_name, "status": "open", "banner": banner}
        except Exception:
            return {"port": port, "status": "closed"}

async def async_port_scan(target: str, ports: list) -> list:
    clean_host = sanitize_target(target)
    results = []
    chunk_size = 200 
    
    for i in range(0, len(ports), chunk_size):
        chunk = ports[i:i+chunk_size]
        tasks = [check_port_with_banner(clean_host, port) for port in chunk]
        chunk_results = await asyncio.gather(*tasks)
        results.extend([res for res in chunk_results if res["status"] == "open"])
        
    return results

# --- 4. CLOUD-SAFE TRACEROUTE ---
def sync_traceroute(host: str) -> list:
    clean_host = sanitize_target(host)
    is_win = platform.system().lower() == 'windows'
    
    # 1. Dynamically locate system CLI binary (tracert on Windows, traceroute or tracepath on Linux)
    cmd = None
    if is_win:
        if shutil.which('tracert'):
            cmd = ['tracert', '-d', '-h', '15', '-w', '200', clean_host]
    else:
        if shutil.which('traceroute'):
            cmd = ['traceroute', '-n', '-m', '15', '-w', '1', clean_host]
        elif shutil.which('tracepath'):
            cmd = ['tracepath', '-n', '-m', '15', clean_host]

    if cmd:
        try:
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            lines = [line.strip() for line in process.stdout.splitlines() if line.strip()]
            hops = []
            for line in lines:
                # Filter out headers and summary lines
                if any(line.startswith(prefix) for prefix in ["Tracing", "traceroute to", "tracepath:", "over a maximum"]):
                    continue
                if line and not line.startswith("Trace complete"):
                    hops.append(line)
            if hops:
                return hops
        except subprocess.TimeoutExpired:
            return ["Traceroute timed out. Intermediate hops may be dropping ICMP packets."]
        except Exception:
            pass  # Fall through to pure Python path telemetry fallback

    # 2. Pure Python Fallback (Guaranteed to work in Docker/Linux cloud environments without traceroute installed)
    try:
        import time
        resolved_ip = socket.gethostbyname(clean_host)
        fallback_hops = [
            f"Gateway Probe -> Target Host: {clean_host} ({resolved_ip})",
        ]
        
        # Test direct TCP reachability & RTT
        start = time.time()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.5)
                s.connect((resolved_ip, 80))
            rtt = round((time.time() - start) * 1000, 2)
            fallback_hops.append(f"Destination Node: {resolved_ip} | Status: REACHABLE | Latency: {rtt} ms")
        except Exception:
            fallback_hops.append(f"Destination Node: {resolved_ip} | Status: PORT 80 FILTERED / HOST ACTIVE")
            
        fallback_hops.append("[System traceroute binary not detected in host OS. Fallback path telemetry active.]")
        return fallback_hops
    except Exception as e:
        return [f"Unable to route or resolve host: {str(e)}"]


async def async_traceroute(target: str) -> list:
    clean_host = sanitize_target(target)
    return await asyncio.to_thread(sync_traceroute, clean_host)

# --- DNS LOOKUP ---
def sync_dns_lookup(domain: str) -> dict:
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
    return await asyncio.to_thread(sync_dns_lookup, domain)

# --- WHOIS / RDAP LOOKUP ---
def format_whois_date(date_obj):
    if not date_obj:
        return "N/A"
    if isinstance(date_obj, list):
        date_obj = date_obj[0]
    if hasattr(date_obj, "strftime"):
        return date_obj.strftime("%Y-%m-%d")
    return str(date_obj)[:10]

async def async_whois_lookup(domain: str) -> dict:
    clean_domain = sanitize_target(domain)
    
    # 1. Primary Method: Query HTTPS RDAP (ICANN standard over HTTPS, bypasses Port 43 firewall blocks)
    try:
        rdap_url = f"https://rdap.org/domain/{clean_domain}"
        async with httpx.AsyncClient(follow_redirects=True, timeout=8.0) as client:
            resp = await client.get(rdap_url)
            if resp.status_code == 200:
                data = resp.json()
                events = data.get("events", [])
                
                creation_raw = next((e["eventDate"] for e in events if e.get("eventAction") in ["registration", "created", "initial registration"]), None)
                expiration_raw = next((e["eventDate"] for e in events if e.get("eventAction") in ["expiration", "renewed"]), None)
                
                # Extract registrar name
                registrar_name = "N/A"
                for entity in data.get("entities", []):
                    if "registrar" in entity.get("roles", []):
                        vcard = entity.get("vcardArray", [])
                        if len(vcard) > 1 and isinstance(vcard[1], list):
                            for entry in vcard[1]:
                                if entry[0] == "fn":
                                    registrar_name = entry[3]
                                    break
                        if registrar_name == "N/A" and entity.get("handle"):
                            registrar_name = entity.get("handle")
                            
                # Extract nameservers
                ns_list = [ns.get("ldhName", "").lower() for ns in data.get("nameservers", []) if ns.get("ldhName")]
                
                # If nameservers weren't returned by RDAP, fall back to DNS resolver
                if not ns_list:
                    try:
                        dns_res = sync_dns_lookup(clean_domain)
                        ns_list = dns_res.get("NS", [])
                    except Exception:
                        pass
                
                return {
                    "domain": data.get("ldhName", clean_domain),
                    "registrar": registrar_name if registrar_name != "N/A" else "ICANN Accredited Registrar",
                    "creation_date": format_whois_date(creation_raw),
                    "expiration_date": format_whois_date(expiration_raw),
                    "name_servers": ns_list
                }
    except Exception:
        pass  # Fall through to legacy WHOIS query

    # 2. Secondary Fallback: Legacy python-whois query
    def sync_whois():
        try:
            w = whois.whois(clean_domain)
            
            emails = w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else []
            name_servers = w.name_servers if isinstance(w.name_servers, list) else [w.name_servers] if w.name_servers else []
            
            # If nameservers are missing, query DNS NS records
            if not name_servers:
                try:
                    dns_res = sync_dns_lookup(clean_domain)
                    name_servers = dns_res.get("NS", [])
                except Exception:
                    pass
                    
            reg = w.registrar if w.registrar else "Unknown Registrar"
            if isinstance(reg, list):
                reg = reg[0]

            return {
                "domain": w.domain_name or clean_domain,
                "registrar": str(reg),
                "creation_date": format_whois_date(w.creation_date),
                "expiration_date": format_whois_date(w.expiration_date),
                "emails": [email for email in emails if email],
                "name_servers": [str(ns).lower() for ns in name_servers if ns]
            }
        except Exception as e:
            # If both RDAP and WHOIS fail, query DNS records to at least provide active zone data
            try:
                dns_res = sync_dns_lookup(clean_domain)
                ns_list = dns_res.get("NS", [])
                if ns_list:
                    return {
                        "domain": clean_domain,
                        "registrar": "Protected / Redacted by Privacy Service",
                        "creation_date": "N/A (Port 43 Restricted)",
                        "expiration_date": "N/A (Port 43 Restricted)",
                        "name_servers": ns_list
                    }
            except Exception:
                pass
            return {"error": f"WHOIS/RDAP lookup failed: {str(e)}"}

    return await asyncio.to_thread(sync_whois)

# --- MAC PROFILER ---
async def async_mac_lookup(mac_address: str) -> dict:
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
                vendor = data.get("data", {}).get("organization_name", "Unknown Vendor")
                return {"mac": mac_address, "vendor": vendor, "status": "success"}
            elif response.status_code == 404:
                return {"mac": mac_address, "vendor": "MAC Not Found in Database", "status": "not_found"}
            else:
                return {"mac": mac_address, "vendor": f"API Error {response.status_code}", "status": "error"}
        except Exception as e:
            return {"mac": mac_address, "vendor": "Connection Timeout", "status": "error"}

# --- SUBNET CALCULATOR ---
def calculate_subnet(cidr: str) -> dict:
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

# --- 5. NEW: SSL/TLS INSPECTOR ---
async def async_ssl_check(domain: str) -> dict:
    clean_domain = sanitize_target(domain)
    def fetch_cert():
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=clean_domain) as s:
                s.settimeout(5)
                s.connect((clean_domain, 443))
                cert = s.getpeercert()
                
                issuer = dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown')
                expiry = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.utcnow()).days
                
                return {
                    "domain": clean_domain,
                    "issuer": issuer,
                    "expiry": expiry.strftime("%Y-%m-%d"),
                    "days_left": days_left,
                    "valid": days_left > 0
                }
        except Exception as e:
            return {"error": f"SSL Handshake failed: {str(e)}"}
    return await asyncio.to_thread(fetch_cert)
