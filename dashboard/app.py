from flask import Flask, render_template, jsonify
from analysis.analyzer import analyze_all

app = Flask(__name__)

@app.route("/")
def index():
    return stats()

@app.route("/stats")
def stats():
    _, stats = analyze_all()
    return render_template(
        "stats.html",
        title="Honeypot Statistics",
        stats=stats,
        active="stats"
    )

@app.route("/ssh")
def ssh():
    rows, _ = analyze_all()
    rows = [r for r in rows if r["service"] == "SSH"]
    return render_template(
        "logs.html",
        title="SSH Logs",
        rows=rows,
        active="ssh"
    )

@app.route("/ftp")
def ftp():
    rows, _ = analyze_all()
    rows = [r for r in rows if r["service"] == "FTP"]
    return render_template(
        "logs.html",
        title="FTP Logs",
        rows=rows,
        active="ftp"
    )

@app.route("/http")
def http():
    rows, _ = analyze_all()
    rows = [r for r in rows if r["service"] == "HTTP"]
    return render_template(
        "logs.html",
        title="HTTP Logs",
        rows=rows,
        active="http"
    )

@app.route("/api/stats")
def api_stats():
    _, stats = analyze_all()
    return jsonify(stats)

if __name__ == "__main__":
    app.run(debug=True)
