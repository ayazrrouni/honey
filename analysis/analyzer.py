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
    "LFI_ATTEMPT": "High",
    "BRUTE_FORCE_ATTEMPT": "Medium",
    "ADMIN_LOGIN": "Medium",
    "ADMIN_DASHBOARD": "Low",
    "VISIT": "Low"
}

SEVERITY_ORDER = ["Low", "Medium", "High"]

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
    data = defaultdict(lambda: {
        "ip": "",
        "country": "LOCAL",
        "pages": set(),
        "attack_types": set(),
        "sessions": 0,
        "inputs": [],
        "last_seen": ""
    })

    if not ATTACKS_LOG.exists():
        return []

    with open(ATTACKS_LOG, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split(" | ", 3)
            if len(parts) < 4:
                continue

            time_str, service, attack, details = parts
            if service != "HTTP":
                continue

            # ===== IP =====
            ip_match = re.search(r"IP=([\d\.]+)", details)
            if ip_match:
                ip = ip_match.group(1)
            else:
                # VISIT case: "/ from 127.0.0.1"
                ip = details.split()[-1]

            row = data[ip]
            row["ip"] = ip
            row["sessions"] += 1
            row["attack_types"].add(attack)
            row["last_seen"] = time_str

            # ===== PAGE (only VISIT) =====
            if attack == "VISIT" and " from " in details:
                page = details.split(" from ")[0].strip()
                row["pages"].add(page)

            # ===== INPUTS / PAYLOADS (remove IP) =====
            if any(x in details for x in ["USER=", "PASS=", "PAYLOAD=", "FILE="]):
                clean = re.sub(r"IP=[\d\.]+\s*", "", details)
                row["inputs"].append(clean.strip())

    rows = []
    for r in data.values():
        # determine highest severity for this IP
        severity = "Low"
        for a in r["attack_types"]:
            s = HTTP_ATTACK_SEVERITY.get(a, "Low")
            if SEVERITY_ORDER.index(s) > SEVERITY_ORDER.index(severity):
                severity = s

        rows.append({
            "service": "HTTP",
            "ip": r["ip"],
            "country": r["country"],
            "pages": list(r["pages"]) if r["pages"] else ["-"],
            "attack_types": list(r["attack_types"]),
            "sessions": r["sessions"],
            "inputs": r["inputs"],
            "commands": len(r["inputs"]),
            "username": "-",
            "password": "-",
            "last_seen": r["last_seen"],
            "last_commands": r["inputs"][-5:],
            "severity": severity
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
        with open(JSON_LOG, "r") as f:
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
        stats["HTTP"]["sessions"] += row["sessions"]
        stats["HTTP"]["commands"] += row["commands"]
        stats["HTTP"][row["severity"].lower()] += 1

    for svc in stats:
        stats[svc]["ips"] = len(seen_ips[svc])

    return rows, stats
