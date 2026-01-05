import json
import re
from pathlib import Path
from collections import defaultdict
from datetime import datetime

# ========= PATHS =========
BASE_DIR = Path(__file__).resolve().parent.parent
JSON_LOG = BASE_DIR / "logs" / "sessions.json"
ATTACKS_LOG = BASE_DIR / "logs" / "attacks.log"

# ========= CONSTANTS =========
DANGEROUS_CMDS = [
    "wget", "curl", "nc", "netcat", "bash", "sh",
    "chmod", "chown", "crontab", "scp", "ftp",
    "python", "perl", "ruby", "nohup"
]

HTTP_ATTACK_SEVERITY = {
    "SQL_INJECTION": "High",
    "LFI": "High",
    "BRUTE_FORCE_ATTEMPT": "Medium",
    "ADMIN_LOGIN": "Medium",
    "ADMIN_DASHBOARD": "Low",
    "VISIT": "Low"
}

SEVERITY_COLOR = {
    "High": "red",
    "Medium": "orange",
    "Low": "green"
}

# ========= SEVERITY =========
def calculate_severity(service, commands):
    score = 0
    if service == "SSH":
        score += 3
    elif service == "FTP":
        score += 2
    else:
        score += 1

    score += len(commands)

    for cmd in commands:
        for bad in DANGEROUS_CMDS:
            if bad in cmd.lower():
                score += 5

    if score >= 12:
        return "High"
    elif score >= 6:
        return "Medium"
    return "Low"


# ========= HTTP PARSER =========
def parse_http_attacks():
    rows = []

    if not ATTACKS_LOG.exists():
        return rows

    with open(ATTACKS_LOG, "r", encoding="utf-8", errors="ignore") as f:
        for idx, line in enumerate(f, start=1):
            parts = line.strip().split(" | ", 3)
            if len(parts) < 4:
                continue

            time_str, service, attack, details = parts
            if service != "HTTP":
                continue

            ip = re.search(r"IP=([\d\.]+)", details)
            user = re.search(r"USER=([^\s]+)", details)
            pwd = re.search(r"PASS=([^\s]+)", details)
            payload = re.search(r"PAYLOAD=(.+)", details)

            rows.append({
                "id": idx,
                "service": "HTTP",
                "ip": ip.group(1) if ip else "UNKNOWN",
                "country": "LOCAL",
                "attack": attack,
                "severity": HTTP_ATTACK_SEVERITY.get(attack, "Low"),
                "sessions": 1,
                "commands": len(payload.group(1).split()) if payload else 0,
                "username": user.group(1) if user else "-",
                "password": pwd.group(1) if pwd else "-",
                "last_seen": time_str,
                "last_commands": [],  # ضروري للـ dashboard
                "payload": payload.group(1).strip() if payload else details
            })

    return rows


# ========= MAIN ANALYZE =========
def analyze_all():
    rows = []
    seen_ips = defaultdict(set)

    stats = {
        "SSH": {"ips": 0, "sessions": 0, "commands": 0, "high": 0, "medium": 0, "low": 0},
        "FTP": {"ips": 0, "sessions": 0, "commands": 0, "high": 0, "medium": 0, "low": 0},
        "HTTP": {"ips": 0, "sessions": 0, "commands": 0, "high": 0, "medium": 0, "low": 0},
    }

    # ===== SSH / FTP =====
    if JSON_LOG.exists():
        with open(JSON_LOG) as f:
            data = json.load(f)

        for ip, info in data.items():
            for s in info.get("sessions", []):
                service = s.get("service")
                if service not in ("SSH", "FTP"):
                    continue

                commands = [c["cmd"] for c in s.get("commands", [])]
                severity = calculate_severity(service, commands)

                last_time = s.get("end_time") or s.get("start_time")
                last_seen = (
                    datetime.fromisoformat(last_time).strftime("%Y-%m-%d %H:%M")
                    if last_time else "-"
                )

                rows.append({
                    "service": service,
                    "ip": ip,
                    "country": info.get("country", "LOCAL"),
                    "attack": "SESSION",
                    "severity": severity,
                    "sessions": 1,
                    "commands": len(commands),
                    "username": s.get("username", "-") or "-",
                    "password": s.get("password", "-") or "-",
                    "last_seen": last_seen,
                    "last_commands": commands[-5:]
                })

                seen_ips[service].add(ip)
                stats[service]["sessions"] += 1
                stats[service]["commands"] += len(commands)
                stats[service][severity.lower()] += 1

    # ===== HTTP =====
    for row in parse_http_attacks():
        rows.append(row)
        seen_ips["HTTP"].add(row["ip"])
        stats["HTTP"]["sessions"] += 1
        stats["HTTP"]["commands"] += row["commands"]
        stats["HTTP"][row["severity"].lower()] += 1

    for svc in stats:
        stats[svc]["ips"] = len(seen_ips[svc])

    return rows, stats
