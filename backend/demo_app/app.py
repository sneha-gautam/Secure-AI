from flask import Flask, render_template, request, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)

@app.after_request
def set_security_headers(response):
    if SECURITY_HEADERS_ENABLED:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

app.secret_key = "secureai-demo-secret-key"
VULN_SQLI_ENABLED = os.environ.get("VULN_SQLI_ENABLED", "false").lower() == "true"
VULN_XSS_ENABLED = os.environ.get("VULN_XSS_ENABLED", "false").lower() == "true"
SECURITY_HEADERS_ENABLED = os.environ.get("SECURITY_HEADERS_ENABLED", "false").lower() == "true"

DB_PATH = os.path.join(os.path.dirname(__file__), "demo.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password_hash TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY,
            username TEXT,
            comment TEXT
        )
    """)

    conn.commit()
    conn.close()


def seed_users():
    conn = get_db()

    users = [
        ("admin", generate_password_hash("Admin@123")),
        ("alice", generate_password_hash("Alice@123"))
    ]

    for username, password_hash in users:
        existing_user = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if existing_user is None:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash)
            )
def seed_comments():
    conn = get_db()

    comments = [
        ("admin", "Welcome to SecureAI"),
        ("alice", "This is a demo application"),
        ("admin", "Security testing is important"),
        ("alice", "Learning Flask and SQLite")
    ]

    for username, comment in comments:
        existing_comment = conn.execute(
            "SELECT id FROM comments WHERE username = ? AND comment = ?",
            (username, comment)
        ).fetchone()

        if existing_comment is None:
            conn.execute(
                "INSERT INTO comments (username, comment) VALUES (?, ?)",
                (username, comment)
            )

    conn.commit()
    conn.close()

@app.route("/comments", methods=["GET", "POST"])
def comments():
    if "user_id" not in session:
        return "Please login first"

    conn = get_db()

    if request.method == "POST":
        comment = request.form["comment"]
        username = session["username"]

        conn.execute(
            "INSERT INTO comments (username, comment) VALUES (?, ?)",
            (username, comment)
        )

        conn.commit()

    comments = conn.execute(
        "SELECT username, comment FROM comments ORDER BY id DESC"
    ).fetchall()

    conn.close()

    return render_template(
    "comments.html",
    comments=comments,
    vuln_xss_enabled=VULN_XSS_ENABLED
)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form["username"]
    password = request.form["password"]

    conn = get_db()

    user = conn.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    conn.close()

    if user is None:
        return "Invalid username or password"

    if check_password_hash(user["password_hash"], password):
        session["user_id"] = user["id"]
        session["username"] = user["username"]

        return "Login successful"

    return "Invalid username or password"


@app.route("/profile")
def profile():
    if "user_id" not in session:
        return "Please login first"

    return render_template(
        "profile.html",
        username=session["username"],
        user_id=session["user_id"]
    )


@app.route("/")
def index():
    return render_template("base.html")


@app.route("/about")
def about():
    return "This is the SecureAI demo application."


@app.route("/health")
def health():
    return "OK"

@app.route("/search")
def search():
    query = request.args.get("query", "")

    if query == "":
        return render_template("search.html")

    conn = get_db()

    if VULN_SQLI_ENABLED:
        # INTENTIONALLY VULNERABLE — controlled test state only, toggled via env var
        sql = f"SELECT username, comment FROM comments WHERE comment LIKE '%{query}%'"
        results = conn.execute(sql).fetchall()
    else:
        results = conn.execute(
            "SELECT username, comment FROM comments WHERE comment LIKE ?",
            (f"%{query}%",)
        ).fetchall()

    conn.close()

    return render_template(
        "search.html",
        query=query,
        results=results
    )


if __name__ == "__main__":
    init_db()
    seed_users()
    seed_comments()
    app.run(debug=True, port=5002)