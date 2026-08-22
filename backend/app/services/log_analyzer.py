import re
from collections import Counter
from typing import List, Dict, Any

# Web Application Signatures
WEB_PATTERNS = {
    "SQL Injection (SQLi)": re.compile(r"(union.*select|select.*from|or\s+1=1|'\s*or\s*'|--|\bexec\b|\bdrop\b)", re.IGNORECASE),
    "Cross-Site Scripting (XSS)": re.compile(r"(<script|javascript:|onerror=|onload=|eval\(|<svg)", re.IGNORECASE),
    "Path Traversal / LFI": re.compile(r"(\.\./\.\.|/etc/passwd|/proc/self|boot\.ini|win\.ini)", re.IGNORECASE),
    "Automated Scanner Activity": re.compile(r"(nikto|sqlmap|gobuster|dirbuster|nmap|acunetix|wpscan|masscan)", re.IGNORECASE),
    "Sensitive File Probing": re.compile(r"(\.env|\.git/|wp-config\.php|\.htaccess|backup\.sql|phpinfo\.php|shell\.php)", re.IGNORECASE),
}

# Linux Auth & SSH Signatures
AUTH_PATTERNS = {
    "SSH Failed Login": re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+", re.IGNORECASE),
    "SSH Accepted Login": re.compile(r"Accepted (password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port \d+", re.IGNORECASE),
    "SSH Invalid User Probing": re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)", re.IGNORECASE),
    "Sudo Command Execution": re.compile(r"sudo:\s+(?P<user>\S+) : TTY=\S+ ; COMMAND=(?P<cmd>.*)", re.IGNORECASE),
}

# Windows Event Log & Application Signatures
WINDOWS_PATTERNS = {
    "Windows Logon Failure (Event 4625)": re.compile(r"(Event\s*ID:?\s*4625|EventID=[\"']?4625[\"']?|An account failed to log on|Audit Failure.*(Logon|4625))", re.IGNORECASE),
    "Windows Security Log Cleared (Event 1102/104)": re.compile(r"(Event\s*ID:?\s*(1102|104)|The audit log was cleared|Audit log cleared|Log clear event)", re.IGNORECASE),
    "Windows New Service Installed (Event 7045)": re.compile(r"(Event\s*ID:?\s*7045|A service was installed in the system|Service Creation:?\s*\S+)", re.IGNORECASE),
    "Windows User Account Created (Event 4720)": re.compile(r"(Event\s*ID:?\s*4720|A user account was created)", re.IGNORECASE),
    "Windows Admin Group Modification (Event 4728/4732)": re.compile(r"(Event\s*ID:?\s*(4728|4732|4756)|A member was added to a security-enabled (global|local|universal) group)", re.IGNORECASE),
    "Windows Process / LOLBin Execution (Event 4688)": re.compile(r"(Event\s*ID:?\s*4688.*(powershell|cmd\.exe|whoami|mimikatz|certutil|vssadmin|rundll32|psexec|net\.exe)|New Process Name:.*(powershell|cmd\.exe|whoami|mimikatz|certutil|vssadmin|rundll32))", re.IGNORECASE),
    "Windows PowerShell Script Block (Event 4104)": re.compile(r"(Event\s*ID:?\s*4104|Script Block Text|Execute a Remote Command.*PowerShell)", re.IGNORECASE),
    "Windows Successful Logon (Event 4624)": re.compile(r"(Event\s*ID:?\s*4624|EventID=[\"']?4624[\"']?|An account was successfully logged on)", re.IGNORECASE),
    "Windows Application Crash / Exception": re.compile(r"(Faulting application name:|Exception code:\s*0x[0-9a-fA-F]+|Event\s*ID:?\s*1000.*Application Error|Windows Error Reporting.*Event\s*ID:?\s*1001)", re.IGNORECASE),
}

# Network / Firewall Signatures
FIREWALL_PATTERNS = {
    "UFW/IPTables Blocked Inbound": re.compile(r"\[UFW BLOCK\]\s+IN=\S+.*SRC=(?P<ip>\S+).*DST=(?P<dst>\S+).*PROTO=(?P<proto>\S+).*DPT=(?P<port>\d+)", re.IGNORECASE),
    "Generic Drop Event": re.compile(r"(DROP|DENY|REJECT)\s+.*SRC=(?P<ip>\S+)", re.IGNORECASE)
}

# Combined Regex for Nginx/Apache standard logs
APACHE_REGEX = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d{3})\s+(?P<size>\S+)\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
)

def parse_and_analyze_logs(log_text: str) -> dict:
    lines = log_text.strip().splitlines()
    total_lines = len(lines)
    
    detected_threats = []
    ip_counter = Counter()
    status_counter = Counter()
    threat_type_counter = Counter()
    failed_auth_ips = Counter()

    for idx, line in enumerate(lines, 1):
        if not line.strip():
            continue

        ip = "Unknown"
        matched_threat = False

        # Extract IP from anywhere in the string to ensure it never fails
        raw_ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
        if raw_ip_match:
            ip = raw_ip_match.group(0)
            if not (ip.startswith("0.") or ip == "255.255.255.255"):
                ip_counter[ip] += 1

        # Extract status code if it's a cleanly formatted web log
        web_match = APACHE_REGEX.match(line)
        if web_match:
            status_counter[web_match.group("status")] += 1

        # 1. Check Web Application Logs (Scans the raw line to catch unencoded SQLi spaces)
        for name, pattern in WEB_PATTERNS.items():
            if pattern.search(line):
                threat_type_counter[name] += 1
                detected_threats.append({
                    "line": idx,
                    "ip": ip,
                    "category": "Web Security",
                    "threat": name,
                    "severity": "High" if "SQL" in name or "Traversal" in name else "Medium",
                    "raw": line[:150] + ("..." if len(line) > 150 else "")
                })
                matched_threat = True
                break

        if matched_threat:
            continue

        # 2. Check Linux Auth / SSH Logs
        for name, pattern in AUTH_PATTERNS.items():
            auth_match = pattern.search(line)
            if auth_match:
                group_dict = auth_match.groupdict()
                user = group_dict.get("user", "unknown")
                
                if "Failed" in name or "Invalid" in name:
                    failed_auth_ips[ip] += 1

                threat_type_counter[name] += 1
                detected_threats.append({
                    "line": idx,
                    "ip": ip,
                    "category": "Linux Authentication",
                    "threat": f"{name} (User: {user})",
                    "severity": "High" if "Failed" in name or "Sudo" in name else "Low",
                    "raw": line[:150] + ("..." if len(line) > 150 else "")
                })
                matched_threat = True
                break

        if matched_threat:
            continue

        # 3. Check Windows Event Logs & Application Logs
        for name, pattern in WINDOWS_PATTERNS.items():
            if pattern.search(line):
                # Try extracting Windows Account Name
                user_match = re.search(r'(Account Name|TargetUserName|User):\s*([^\s,;]+)', line, re.IGNORECASE)
                user = user_match.group(2) if user_match else "SYSTEM"

                if "Failure" in name or "4625" in name:
                    failed_auth_ips[ip if ip != "Unknown" else f"User:{user}"] += 1

                severity = "Critical" if "Cleared" in name or "Group Modification" in name or "LOLBin" in name else "High" if "Failure" in name or "Service" in name else "Medium"
                
                threat_type_counter[name] += 1
                detected_threats.append({
                    "line": idx,
                    "ip": ip,
                    "category": "Windows Security & System",
                    "threat": f"{name} (User: {user})",
                    "severity": severity,
                    "raw": line[:150] + ("..." if len(line) > 150 else "")
                })
                matched_threat = True
                break

        if matched_threat:
            continue

        # 4. Check Firewall Logs
        for name, pattern in FIREWALL_PATTERNS.items():
            fw_match = pattern.search(line)
            if fw_match:
                threat_type_counter[name] += 1
                detected_threats.append({
                    "line": idx,
                    "ip": ip,
                    "category": "Network / Firewall",
                    "threat": name,
                    "severity": "Medium",
                    "raw": line[:150] + ("..." if len(line) > 150 else "")
                })
                break

    # Detect Brute-force spikes
    brute_force_alerts = []
    for source, count in failed_auth_ips.items():
        if count >= 3:
            brute_force_alerts.append({
                "ip": source,
                "failed_attempts": count,
                "assessment": f"Potential Brute-Force / Password Spray ({count} failed attempts)"
            })

    return {
        "summary": {
            "total_lines": total_lines,
            "total_threats": len(detected_threats),
            "threat_distribution": dict(threat_type_counter),
            "top_source_ips": [{"ip": k, "count": v} for k, v in ip_counter.most_common(5) if k != "Unknown"],
            "http_status_codes": dict(status_counter),
            "brute_force_alerts": brute_force_alerts
        },
        "flagged_events": detected_threats[:100]
    }
