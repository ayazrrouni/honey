import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent.parent
JSON_LOG = BASE_DIR / "logs" / "sessions.json"

# ================= DANGEROUS COMMANDS (SSH / FTP) =================
DANGEROUS_CMDS = [
    "wget", "curl", "nc", "netcat", "bash", "sh",
    "chmod", "chown", "crontab", "scp", "ftp",
    "python", "perl", "ruby", "nohup"
]

# ================= HTTP ATTACK SEVERITY =================
HTTP_ATTACK_SEVERITY = {
    "SQL_INJECTION": "High",
    "LFI": "High",
    "BRUTE_FORCE": "Medium",
    "ADMIN_LOGIN": "Medium",
    "VISIT": "Low",
}

SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3}


# ================= SSH / FTP SEVERITY =================
def calculate_severity(service, commands):
    score = 0

    if service == "SSH":
        score += 3
    elif service == "FTP":
        score += 2

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


# ================= ANALYZER =================
def analyze_all():
    if not JSON_LOG.exists():
        return [], {}

    with open(JSON_LOG) as f:
        data = json.load(f)

    rows = []

    # ================= HTTP AGGREGATION (PER IP) =================
    http_ips = defaultdict(lambda: {
        "sessions": 0,
        "usernames": set(),
        "passwords": set(),
        "attacks": set(),
        "payloads": set(),
        "last_seen": None,
        "severity": "Low"
    })

    stats = {
        "SSH": {"ips": set(), "sessions": 0, "commands": 0, "high": 0, "medium": 0, "low": 0},
        "FTP": {"ips": set(), "sessions": 0, "commands": 0, "high": 0, "medium": 0, "low": 0},
        "HTTP": {"ips": set(), "sessions": 0, "commands": 0, "high": 0, "medium": 0, "low": 0},
    }

    for ip, info in data.items():
        for s in info.get("sessions", []):
            service = s.get("service")

            # ================= HTTP =================
            if service == "HTTP":
                http = http_ips[ip]
                http["sessions"] += 1

                last_time = s.get("end_time") or s.get("start_time")
                if last_time:
                    http["last_seen"] = last_time

                if s.get("username"):
                    http["usernames"].add(s["username"])
                if s.get("password"):
                    http["passwords"].add(s["password"])

                for c in s.get("commands", []):
                    cmd = c.get("cmd", "")

                    attack = "VISIT"
                    payload = ""

                    if cmd.startswith("SQL_INJECTION"):
                        attack = "SQL_INJECTION"
                        payload = cmd.replace("SQL_INJECTION", "").strip()

                    elif cmd.startswith("LFI"):
                        attack = "LFI"
                        payload = cmd.replace("LFI", "").strip()

                    elif cmd.startswith("BRUTE_FORCE"):
                        attack = "BRUTE_FORCE"
                        payload = cmd.replace("BRUTE_FORCE", "").strip()

                    elif cmd.startswith("ADMIN_LOGIN"):
                        attack = "ADMIN_LOGIN"
                        payload = cmd.replace("ADMIN_LOGIN", "").strip()

                    http["attacks"].add(attack)

                    if payload:
                        http["payloads"].add(payload)

                    sev = HTTP_ATTACK_SEVERITY.get(attack, "Low")
                    if SEVERITY_RANK[sev] > SEVERITY_RANK[http["severity"]]:
                        http["severity"] = sev

                    stats["HTTP"][sev.lower()] += 1

                stats["HTTP"]["sessions"] += 1
                stats["HTTP"]["ips"].add(ip)

            # ================= SSH / FTP =================
            elif service in ("SSH", "FTP"):
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
                    "severity": severity,
                    "sessions": 1,
                    "commands": len(commands),
                    "username": s.get("username", "-"),
                    "password": s.get("password", "-"),
                    "last_seen": last_seen,
                    "last_commands": commands[-5:]
                })

                stats[service]["sessions"] += 1
                stats[service]["commands"] += len(commands)
                stats[service]["ips"].add(ip)
                stats[service][severity.lower()] += 1

    # ================= FINAL HTTP ROWS =================
    for ip, h in http_ips.items():
        attacks_clean = [a for a in sorted(h["attacks"]) if a != "VISIT"]

        rows.append({
            "service": "HTTP",
            "ip": ip,
            "country": "LOCAL",
            "severity": h["severity"],
            "sessions": h["sessions"],
            "commands": 0,
            "username": ", ".join(sorted(h["usernames"])),
            "password": ", ".join(sorted(h["passwords"])),
            "last_seen": (
                datetime.fromisoformat(h["last_seen"]).strftime("%Y-%m-%d %H:%M")
                if h["last_seen"] else "-"
            ),
            "last_commands": ", ".join(attacks_clean) if attacks_clean else "VISIT",
            "payload": ", ".join(sorted(h["payloads"]))
        })

    # ================= CLEAN STATS =================
    for svc in stats:
        stats[svc]["ips"] = len(stats[svc]["ips"])

    return rows, stats
