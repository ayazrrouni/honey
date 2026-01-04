from flask import Flask, render_template
from analysis.analyzer import analyze_all

# ✅ لازم يكون هذا قبل routes
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
        title="SSH Attacks",
        rows=rows,
        active="ssh"
    )

@app.route("/ftp")
def ftp():
    rows, _ = analyze_all()
    rows = [r for r in rows if r["service"] == "FTP"]
    return render_template(
        "logs.html",
        title="FTP Attacks",
        rows=rows,
        active="ftp"
    )

@app.route("/http")
def http():
    rows, _ = analyze_all()
    rows = [r for r in rows if r["service"] == "HTTP"]
    return render_template(
        "logs.html",
        title="HTTP Attacks",
        rows=rows,
        active="http"
    )

# ✅ هذا ضروري كي تشغل python3 -m dashboard.app
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
