import os
from collections import defaultdict
from datetime import datetime

LOG_DIR = "logs"
CMD_LOG = os.path.join(LOG_DIR, "cmd_audits.log")

# =========================
# Severity rules
# =========================
DANGEROUS_CMDS = [
    "wget", "curl", "nc", "netcat", "bash", "sh",
    "chmod", "chown", "crontab", "scp", "ftp",
    "python", "perl", "ruby", "nohup"
]


def calculate_severity(service, commands):
    """
    Calculate severity based on:
    - Service type
    - Number of commands
    - Dangerous keywords
    """
    score = 0

    # Service weight
    if service == "SSH":
        score += 3
    elif service == "FTP":
        score += 2
    else:
        score += 1

    # Number of commands
    score += len(commands)

    # Dangerous commands
    for cmd in commands:
        for bad in DANGEROUS_CMDS:
            if bad in cmd.lower():
                score += 5

    if score >= 12:
        return "High"
    elif score >= 6:
        return "Medium"
    return "Low"


# =========================
# Utils
# =========================
def parse_time(line):
    try:
        return datetime.fromisoformat(line.split(" ")[0])
    except Exception:
        return None


def extract_ip(line):
    if "IP=" in line:
        return line.split("IP=")[1].split()[0]
    if " - " in line:
        return line.split(" - ")[1].strip()
    return "Unknown"


# =========================
# Commands Analyzer
# =========================
def analyze_commands():
    """
    Reads logs/cmd_audits.log
    Format:
    [2026-01-04 05:40:01] 10.0.0.5 | root | uname -a
    """
    result = defaultdict(lambda: {
        "count": 0,
        "last_commands": [],
        "last_seen": None
    })

    if not os.path.exists(CMD_LOG):
        return result

    with open(CMD_LOG) as f:
        for line in f:
            try:
                time_part, rest = line.split("] ", 1)
                ts = datetime.strptime(time_part[1:], "%Y-%m-%d %H:%M:%S")

                ip, user, cmd = rest.strip().split(" | ", 2)

                row = result[ip]
                row["count"] += 1
                row["last_commands"].append(cmd)
                row["last_seen"] = ts
            except Exception:
                continue

    # Keep last 5 commands only
    for r in result.values():
        r["last_commands"] = r["last_commands"][-5:]

    return result


# =========================
# SSH Analyzer
# =========================
def analyze_ssh():
    path = os.path.join(LOG_DIR, "ssh_auth.log")
    cmd_data = analyze_commands()

    data = defaultdict(lambda: {
        "service": "SSH",
        "ip": "",
        "country": "N/A",
        "severity": "Low",
        "sessions": 0,
        "commands": 0,
        "last_seen": None,
        "last_commands": []
    })

    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                if "IP=" not in line:
                    continue

                ip = extract_ip(line)
                ts = parse_time(line)

                row = data[ip]
                row["ip"] = ip
                row["sessions"] += 1

                if ts and (not row["last_seen"] or ts > row["last_seen"]):
                    row["last_seen"] = ts

    # Merge commands + calculate severity
    for ip, cmds in cmd_data.items():
        row = data[ip]
        row["ip"] = ip
        row["commands"] = cmds["count"]
        row["last_commands"] = cmds["last_commands"]

        if cmds["last_seen"] and (
            not row["last_seen"] or cmds["last_seen"] > row["last_seen"]
        ):
            row["last_seen"] = cmds["last_seen"]

        row["severity"] = calculate_severity(
            "SSH",
            row["last_commands"]
        )

    return list(data.values())


# =========================
# FTP Analyzer
# =========================
def analyze_ftp():
    path = os.path.join(LOG_DIR, "ftp_backdoor.log")

    data = defaultdict(lambda: {
        "service": "FTP",
        "ip": "",
        "country": "N/A",
        "severity": "Low",
        "sessions": 0,
        "commands": 0,
        "last_seen": None,
        "last_commands": []
    })

    if not os.path.exists(path):
        return []

    with open(path) as f:
        for line in f:
            if "Backdoor connection established" in line:
                ip = extract_ip(line)
                ts = parse_time(line)

                row = data[ip]
                row["ip"] = ip
                row["sessions"] += 1
                row["last_seen"] = ts

            elif "CMD:" in line:
                ip = extract_ip(line)
                cmd = line.split("CMD:")[1].strip()
                ts = parse_time(line)

                row = data[ip]
                row["ip"] = ip
                row["commands"] += 1
                row["last_seen"] = ts
                row["last_commands"].append(cmd)

    for r in data.values():
        r["last_commands"] = r["last_commands"][-5:]
        r["severity"] = calculate_severity(
            "FTP",
            r["last_commands"]
        )

    return list(data.values())


# =========================
# HTTP Analyzer (future)
# =========================
def analyze_http():
    return []


# =========================
# Global Analyzer
# =========================
def analyze_all():
    rows = []
    rows += analyze_ssh()
    rows += analyze_ftp()
    rows += analyze_http()

    for r in rows:
        r["last_seen"] = (
            r["last_seen"].strftime("%Y-%m-%d %H:%M")
            if r["last_seen"] else "-"
        )

    return rows
