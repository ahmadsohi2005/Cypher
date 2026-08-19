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

# Network / Firewall Signatures
FIREWALL_PATTERNS = {
    "UFW/IPTables Blocked Inbound": re.compile(r"\[UFW BLOCK\]\s+IN=\S+.*SRC=(?P<ip>\S+).*DST=(?P<dst>\S+).*PROTO=(?P<proto>\S+).*DPT=(?P<port>\d+)", re.IGNORECASE),
    "Generic Drop Event": re.compile(r"(DROP|DENY|REJECT)\s+.*SRC=(?P<ip>\S+)", re.IGNORECASE)
}

# Combined Regex for Nginx/Apache standard logs
APACHE_REGEX = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d{3})\s+(?P<size>\S+)\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
)

def parse_and_analyze_logs(log_text: str) -> Dict[str, Any]:
    lines = log_text.strip().splitlines()
    total_lines = len(lines)
    
    detected_threats: List[Dict[str, Any]] = []
    ip_counter = Counter()
    status_counter = Counter()
    threat_type_counter = Counter()
    failed_ssh_ips = Counter()

    for idx, line in enumerate(lines, 1):
        if not line.strip():
            continue

        ip = "Unknown"
        matched_threat = False

        # Check Web Application Logs
        web_match = APACHE_REGEX.match(line)
        if web_match:
            data = web_match.groupdict()
            ip = data["ip"]
            status = data["status"]
            status_counter[status] += 1
            search_str = f"{data['path']} {data['user_agent']}"

            for name, pattern in WEB_PATTERNS.items():
                if pattern.search(search_str):
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
        else:
            # Check Linux Auth / SSH Logs
            for name, pattern in AUTH_PATTERNS.items():
                auth_match = pattern.search(line)
                if auth_match:
                    group_dict = auth_match.groupdict()
                    ip = group_dict.get("ip", ip)
                    user = group_dict.get("user", "unknown")
                    
                    if "Failed" in name or "Invalid" in name:
                        failed_ssh_ips[ip] += 1

                    threat_type_counter[name] += 1
                    detected_threats.append({
                        "line": idx,
                        "ip": ip,
                        "category": "Authentication",
                        "threat": f"{name} (User: {user})",
                        "severity": "High" if "Failed" in name or "Sudo" in name else "Low",
                        "raw": line[:150] + ("..." if len(line) > 150 else "")
                    })
                    matched_threat = True
                    break

            # Check Firewall Logs
            if not matched_threat:
                for name, pattern in FIREWALL_PATTERNS.items():
                    fw_match = pattern.search(line)
                    if fw_match:
                        group_dict = fw_match.groupdict()
                        ip = group_dict.get("ip", ip)
                        threat_type_counter[name] += 1
                        detected_threats.append({
                            "line": idx,
                            "ip": ip,
                            "category": "Network / Firewall",
                            "threat": name,
                            "severity": "Medium",
                            "raw": line[:150] + ("..." if len(line) > 150 else "")
                        })
                        matched_threat = True
                        break

        # Fallback IP extraction
        if ip == "Unknown":
            raw_ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            if raw_ip_match:
                ip = raw_ip_match.group(0)

        if ip != "Unknown":
            ip_counter[ip] += 1

    # Detect Brute-force spikes
    brute_force_alerts = []
    for source_ip, count in failed_ssh_ips.items():
        if count >= 3:
            brute_force_alerts.append({
                "ip": source_ip,
                "failed_attempts": count,
                "assessment": "Potential SSH Brute-Force / Password Spraying"
            })

    return {
        "summary": {
            "total_lines": total_lines,
            "total_threats": len(detected_threats),
            "threat_distribution": dict(threat_type_counter),
            "top_source_ips": [{"ip": k, "count": v} for k, v in ip_counter.most_common(5)],
            "http_status_codes": dict(status_counter),
            "brute_force_alerts": brute_force_alerts
        },
        "flagged_events": detected_threats[:60]
    }