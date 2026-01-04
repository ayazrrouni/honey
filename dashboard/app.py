from flask import Flask, render_template
from analysis.analyzer import (
    analyze_ssh,
    analyze_ftp,
    analyze_http
)

app = Flask(__name__)

@app.route("/ssh")
def ssh():
    rows = analyze_ssh()
    return render_template(
        "logs.html",
        title="SSH Honeypot Dashboard",
        rows=rows,
        active="ssh"
    )

@app.route("/ftp")
def ftp():
    rows = analyze_ftp()
    return render_template(
        "logs.html",
        title="FTP Honeypot Dashboard",
        rows=rows,
        active="ftp"
    )

@app.route("/http")
def http():
    rows = analyze_http()
    return render_template(
        "logs.html",
        title="HTTP Honeypot Dashboard",
        rows=rows,
        active="http"
    )

@app.route("/")
def index():
    return ssh()

app.run(debug=True)
