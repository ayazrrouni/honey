import json
from pathlib import Path
from datetime import datetime
from threading import Lock
import requests

lock = Lock()

BASE_DIR = Path(__file__).resolve().parent.parent
JSON_LOG = BASE_DIR / "logs" / "sessions.json"

DANGEROUS = ["wget", "curl", "nc", "bash", "chmod", "scp"]


def _load():
    if JSON_LOG.exists():
        with open(JSON_LOG, "r") as f:
            return json.load(f)
    return {}


def _save(data):
    JSON_LOG.parent.mkdir(exist_ok=True)
    with open(JSON_LOG, "w") as f:
        json.dump(data, f, indent=2)


def start_session(ip, session_id, service="ssh"):
    with lock:
        data = _load()

        if ip not in data:
            data[ip] = {
                "country": get_country(ip),
                "severity": "LOW",
                "last_seen": None,
                "sessions": []
            }

        data[ip]["sessions"].append({
            "id": session_id,
            "service": service.upper(),
            "start_time": datetime.now().isoformat(),
            "end_time": None,
            "commands": [],
            "username": None,
            "password": None
        })

        data[ip]["last_seen"] = datetime.now().isoformat()
        _save(data)


def log_command(ip, session_id, command):
    with lock:
        data = _load()

        for s in data.get(ip, {}).get("sessions", []):
            if s["id"] == session_id:
                s["commands"].append({
                    "cmd": command,
                    "time": datetime.now().isoformat()
                })
                break

        data[ip]["last_seen"] = datetime.now().isoformat()

        all_cmds = [
            c["cmd"]
            for sess in data[ip]["sessions"]
            for c in sess["commands"]
        ]
        data[ip]["severity"] = calc_severity(all_cmds)

        _save(data)


def log_ftp_credentials(ip, session_id, username=None, password=None):
    with lock:
        data = _load()
        for s in data.get(ip, {}).get("sessions", []):
            if s["id"] == session_id:
                if username:
                    s["username"] = username
                if password:
                    s["password"] = password
                break
        _save(data)


def end_session(ip, session_id):
    with lock:
        data = _load()
        for s in data.get(ip, {}).get("sessions", []):
            if s["id"] == session_id and s["end_time"] is None:
                s["end_time"] = datetime.now().isoformat()
                break
        data[ip]["last_seen"] = datetime.now().isoformat()
        _save(data)


def get_country(ip):
    if ip.startswith(("127.", "192.168")):
        return "LOCAL"
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=country",
            timeout=3
        )
        return r.json().get("country", "N/A")
    except:
        return "N/A"


def calc_severity(commands):
    for c in commands:
        for k in DANGEROUS:
            if k in c:
                return "HIGH"
    return "LOW"
