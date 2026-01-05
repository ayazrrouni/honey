from flask import Flask, request, render_template, redirect
import time
import os
import re

app = Flask(
    __name__,
    template_folder="../web/templates",
    static_folder="../web/static"
)

LOG_FILE = "logs/attacks.log"

# ========= LOGGER =========
def log_attack(action, detail):
    os.makedirs("logs", exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(f"{time.ctime()} | HTTP | {action} | {detail}\n")

# ========= ROUTES =========

@app.route("/")
def index():
    log_attack(
        "VISIT",
        f"GET {request.path} IP={request.remote_addr}"
    )
    return render_template("index.html")


@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        log_attack(
            "ADMIN_LOGIN",
            f"POST {request.path} IP={request.remote_addr} USER={username} PASS={password}"
        )

        return redirect("/admin/dashboard")

    log_attack(
        "VISIT",
        f"GET {request.path} IP={request.remote_addr}"
    )
    return render_template("admin.html")


@app.route("/admin/dashboard")
def admin_dashboard():
    log_attack(
        "ADMIN_DASHBOARD",
        f"GET {request.path} IP={request.remote_addr}"
    )
    return render_template("dashboard.html")


@app.route("/download")
def download():
    filename = request.args.get("file", "")

    if "passwd" in filename:
        log_attack(
            "LFI_ATTEMPT",
            f"GET {request.path}?file={filename} IP={request.remote_addr} FILE={filename}"
        )

        fake_passwd = """root:x:0:0:root:/root:/bin/bash
admin:x:1000:1000:admin:/home/admin:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:999:999:mysql:/var/lib/mysql:/bin/false
"""
        return fake_passwd, 200, {"Content-Type": "text/plain"}

    log_attack(
        "VISIT",
        f"GET {request.path}?file={filename} IP={request.remote_addr}"
    )
    return "File not found", 404


@app.route("/bruteforce", methods=["GET", "POST"])
def bruteforce():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        log_attack(
            "BRUTE_FORCE_ATTEMPT",
            f"POST {request.path} IP={request.remote_addr} USER={username} PASS={password}"
        )

        error = "Invalid username or password"

    else:
        log_attack(
            "VISIT",
            f"GET {request.path} IP={request.remote_addr}"
        )

    return render_template("bruteforce.html", error=error)


# ========= SQL INJECTION =========
SQL_PATTERNS = [
    r"('|--|;|/\*|\*/|or\s+1=1|union\s+select|select\s+.*from)",
]

@app.route("/sql_login", methods=["GET", "POST"])
def sql_login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        payload = f"{username} {password}"

        is_sql = any(
            re.search(p, payload, re.IGNORECASE)
            for p in SQL_PATTERNS
        )

        if is_sql:
            log_attack(
                "SQL_INJECTION",
                f"POST {request.path} IP={request.remote_addr} PAYLOAD={payload}"
            )
            error = "SQL syntax error near '' at line 1"
        else:
            log_attack(
                "VISIT",
                f"POST {request.path} IP={request.remote_addr}"
            )
            error = "Invalid credentials"

    else:
        log_attack(
            "VISIT",
            f"GET {request.path} IP={request.remote_addr}"
        )

    return render_template("sql_login.html", error=error)


# ========= START =========
def start_http():
    print("[+] HTTP Honeypot listening on port 80")
    app.run(host="0.0.0.0", port=80, debug=False)
