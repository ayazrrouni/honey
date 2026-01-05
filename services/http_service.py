from flask import Flask, request, render_template, redirect
import uuid
import re

from core.logger import (
    start_session,
    log_command,
    log_ftp_credentials,
    end_session
)

app = Flask(
    __name__,
    template_folder="../web/templates",
    static_folder="../web/static"
)

# ================= HOME =================
@app.route("/")
def index():
    return render_template("index.html")


# ================= ADMIN LOGIN =================
@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        ip = request.remote_addr
        session_id = str(uuid.uuid4())

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        start_session(ip, session_id, service="HTTP")

        if username or password:
            log_ftp_credentials(
                ip,
                session_id,
                username=username,
                password=password
            )

            log_command(
                ip,
                session_id,
                f"ADMIN_LOGIN user={username} pass={password}"
            )

        end_session(ip, session_id)
        return redirect("/admin/dashboard")

    return render_template("admin.html")


@app.route("/admin/dashboard")
def admin_dashboard():
    return render_template("dashboard.html")


# ================= BRUTE FORCE =================
@app.route("/bruteforce", methods=["GET", "POST"])
def bruteforce():
    error = None

    if request.method == "POST":
        ip = request.remote_addr
        session_id = str(uuid.uuid4())

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        start_session(ip, session_id, service="HTTP")

        log_ftp_credentials(
            ip,
            session_id,
            username=username,
            password=password
        )

        log_command(
            ip,
            session_id,
            f"BRUTE_FORCE user={username} pass={password}"
        )

        end_session(ip, session_id)
        error = "Invalid username or password"

    return render_template("bruteforce.html", error=error)


# ================= SQL INJECTION =================
SQL_PATTERNS = [
    r"('|--|;|/\*|\*/|or\s+1=1|union\s+select|select\s+.*from)",
]

@app.route("/sql_login", methods=["GET", "POST"])
def sql_login():
    error = None

    if request.method == "POST":
        ip = request.remote_addr
        session_id = str(uuid.uuid4())

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        payload = f"{username} {password}"

        is_sql = any(re.search(p, payload, re.IGNORECASE) for p in SQL_PATTERNS)

        start_session(ip, session_id, service="HTTP")

        log_ftp_credentials(
            ip,
            session_id,
            username=username,
            password=password
        )

        if is_sql:
            log_command(
                ip,
                session_id,
                f"SQL_INJECTION payload={payload}"
            )
            error = "SQL syntax error near ''"
        else:
            log_command(
                ip,
                session_id,
                f"LOGIN_FAILED payload={payload}"
            )
            error = "Invalid credentials"

        end_session(ip, session_id)

    return render_template("sql_login.html", error=error)


# ================= LFI =================
@app.route("/download")
def download():
    filename = request.args.get("file", "")
    ip = request.remote_addr

    if "passwd" in filename:
        session_id = str(uuid.uuid4())

        start_session(ip, session_id, service="HTTP")
        log_command(ip, session_id, f"LFI file={filename}")
        end_session(ip, session_id)

        fake_passwd = """root:x:0:0:root:/root:/bin/bash
admin:x:1000:1000:admin:/home/admin:/bin/bash
"""
        return fake_passwd, 200, {"Content-Type": "text/plain"}

    return "File not found", 404


# ================= START =================
def start_http():
    print("[+] HTTP Honeypot listening on port 80")
    app.run(host="0.0.0.0", port=80, debug=False)
