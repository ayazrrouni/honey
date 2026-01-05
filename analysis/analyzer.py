import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent.parent
JSON_LOG = BASE_DIR / "logs" / "sessions.json"

DANGEROUS_CMDS = [
    "wget", "curl", "nc", "netcat", "bash", "sh",
    "chmod", "chown", "crontab", "scp", "ftp",
    "python", "perl", "ruby", "nohup"
]

# HTTP severity based on attack type (NOT commands)
HTTP_ATTACK_SEVERITY = {
    "SQL_INJECTION": "High",
    "LFI_ATTEMPT": "High",
    "BRUTE_FORCE_ATTEMPT": "Medium",
    "ADMIN_LOGIN": "Medium",
    "VISIT": "Low",
}


def calculate_severity(service, commands, attack_type=None):
    """
    Calculate severity based on service type.
    - SSH / FTP: score-based (commands + dangerous keywords)
    - HTTP: attack-type based
    """

    # ===== HTTP LOGIC =====
    if service == "HTTP":
        return HTTP_ATTACK_SEVERITY.get(attack_type, "Low")

    # ===== SSH / FTP LOGIC =====
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


def analyze_all():
    if not JSON_LOG.exists():
        return [], {}

    with open(JSON_LOG) as f:
        data = json.load(f)

    rows = []
    seen_ips = defaultdict(set)

    stats = {
        "SSH": {"ips": 0, "sessions": 0, "commands": 0, "high": 0, "medium": 0, "low": 0},
        "FTP": {"ips": 0, "sessions": 0, "commands": 0, "high": 0, "medium": 0, "low": 0},
        "HTTP": {"ips": 0, "sessions": 0, "commands": 0, "high": 0, "medium": 0, "low": 0},
    }

    for ip, info in data.items():
        for s in info.get("sessions", []):
            service = s.get("service", "UNKNOWN")

            # ===== HTTP SESSION =====
            if service == "HTTP":
                attack_type = s.get("attack_type", "VISIT")
                commands = []
                severity = calculate_severity(service, commands, attack_type)

            # ===== SSH / FTP SESSION =====
            else:
                commands = [c["cmd"] for c in s.get("commands", [])]
                severity = calculate_severity(service, commands)

            last_time = s.get("end_time") or s.get("start_time")
            last_seen = (
                datetime.fromisoformat(last_time).strftime("%Y-%m-%d %H:%M")
                if last_time else "-"
            )

            row = {
                "service": service,
                "ip": ip,
                "country": info.get("country", "LOCAL"),
                "severity": severity,
                "sessions": 1,
                "commands": len(commands),
                "username": s.get("username", "-") or "-",
                "password": s.get("password", "-") or "-",
                "last_seen": last_seen,
                "last_commands": commands[-5:]
            }

            rows.append(row)

            if service in stats:
                seen_ips[service].add(ip)
                stats[service]["sessions"] += 1
                stats[service]["commands"] += len(commands)
                stats[service][severity.lower()] += 1

    for svc in stats:
        stats[svc]["ips"] = len(seen_ips[svc])

    return rows, stats
