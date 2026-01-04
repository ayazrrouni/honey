from flask import Flask, render_template
from analysis.analyzer import analyze_all

app = Flask(__name__)

@app.route("/ssh")
def ssh():
    rows, _ = analyze_all()
    rows = [r for r in rows if r["service"] == "SSH"]
    return render_template("logs.html", title="SSH Logs", rows=rows, active="ssh")

@app.route("/ftp")
def ftp():
    rows, _ = analyze_all()
    rows = [r for r in rows if r["service"] == "FTP"]
    return render_template("logs.html", title="FTP Logs", rows=rows, active="ftp")

@app.route("/http")
def http():
    rows, _ = analyze_all()
    rows = [r for r in rows if r["service"] == "HTTP"]
    return render_template("logs.html", title="HTTP Logs", rows=rows, active="http")

@app.route("/stats")
def stats():
    _, stats = analyze_all()
    return render_template("stats.html", title="Honeypot Statistics", stats=stats, active="stats")

@app.route("/")
def index():
    return ssh()

app.run(debug=True)
