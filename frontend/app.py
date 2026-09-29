from flask import Flask, render_template

app = Flask(__name__)

findings = [
    {"name": "SQL Injection", "level": "High", "path": "/search", "tone": "danger"},
    {"name": "Cross-Site Scripting", "level": "Medium", "path": "/comments", "tone": "warning"},
    {"name": "Missing Security Headers", "level": "Medium", "path": "/", "tone": "warning"},
]


@app.route("/")
def dashboard():
    return render_template("dashboard.html", active="dashboard", findings=findings)


@app.route("/scan")
def scan():
    return render_template("scan.html", active="scan")


if __name__ == "__main__":
    app.run(debug=True, port=5003)