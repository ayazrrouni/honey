import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent.parent
JSON_LOG = BASE_DIR / "logs" / "sessions.json"

HTTP_ATTACK_SEVERITY = {
    "SQL_INJECTION": "High",
    "LFI": "High",
    "BRUTE_FORCE": "Medium",
    "ADMIN_LOGIN": "Medium",
    "VISIT": "Low",
}

SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3}


# ================= ATTACK PARSER =================
def parse_http_attack(cmd: str):
    cmd = cmd.strip()

    if cmd.startswith("SQL_INJECTION"):
        return "SQL_INJECTION", cmd
    if cmd.startswith("LOGIN_FAILED") or cmd.startswith("BRUTE_FORCE"):
        return "BRUTE_FORCE", cmd
    if cmd.startswith("ADMIN_LOGIN"):
        return "ADMIN_LOGIN", cmd
    if cmd.startswith("LFI"):
        return "LFI", cmd
    if cmd.startswith("VISIT") or cmd.startswith("ACCESS"):
        return "VISIT", cmd

    return "VISIT", cmd


# ================= ANALYZER =================
def analyze_all():
    if not JSON_LOG.exists():
        return [], {}

    with open(JSON_LOG) as f:
        data = json.load(f)

    rows = []

    http_ips = defaultdict(lambda: {
        "sessions": 0,
        "usernames": set(),
        "passwords": set(),
        "attacks": set(),     # <-- أسماء الهجمات فقط
        "payloads": set(),    # <-- النص الكامل
        "last_seen": None,
        "severity": "Low"
    })

    stats = {
        "HTTP": {"ips": set(), "sessions": 0, "high": 0, "medium": 0, "low": 0}
    }

    for ip, info in data.items():
        for s in info.get("sessions", []):
            if s.get("service") != "HTTP":
                continue

            http = http_ips[ip]
            http["sessions"] += 1
            stats["HTTP"]["sessions"] += 1
            stats["HTTP"]["ips"].add(ip)

            last_time = s.get("end_time") or s.get("start_time")
            if last_time:
                http["last_seen"] = last_time

            if s.get("username"):
                http["usernames"].add(s["username"])
            if s.get("password"):
                http["passwords"].add(s["password"])

            for c in s.get("commands", []):
                raw_cmd = c.get("cmd", "").strip()
                if not raw_cmd:
                    continue

                attack, payload = parse_http_attack(raw_cmd)

                http["attacks"].add(attack)
                http["payloads"].add(payload)

                sev = HTTP_ATTACK_SEVERITY.get(attack, "Low")
                if SEVERITY_RANK[sev] > SEVERITY_RANK[http["severity"]]:
                    http["severity"] = sev

                stats["HTTP"][sev.lower()] += 1

    # ================= FINAL ROW =================
    for ip, h in http_ips.items():
        attack_list = sorted(a for a in h["attacks"] if a != "VISIT")

        rows.append({
            "service": "HTTP",
            "ip": ip,
            "country": "LOCAL",
            "severity": h["severity"],
            "sessions": h["sessions"],
            "username": ", ".join(sorted(h["usernames"])),
            "password": ", ".join(sorted(h["passwords"])),
            "last_seen": (
                datetime.fromisoformat(h["last_seen"]).strftime("%Y-%m-%d %H:%M")
                if h["last_seen"] else "-"
            ),
            # 👇 هذا يبان في Attack:
            "last_commands": ", ".join(attack_list) if attack_list else "VISIT",
            # 👇 هذا يبان في Payload:
            "payload": ", ".join(sorted(h["payloads"]))
        })

    stats["HTTP"]["ips"] = len(stats["HTTP"]["ips"])
    return rows, stats
