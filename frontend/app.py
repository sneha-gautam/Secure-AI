from flask import Flask, render_template, request, jsonify
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANNER_DIR = os.path.join(PROJECT_ROOT, "backend", "scanner")

if SCANNER_DIR not in sys.path:
    sys.path.insert(0, SCANNER_DIR)

from scanner import run_scan
from validator import validate_all
from remediation import apply_patch

app = Flask(__name__)
 
findings = [
    {
        "name": "SQL Injection",
        "level": "High",
        "path": "/search",
        "tone": "danger",
        "description":"Unsanitized user input in query parameter executed directly in SQL query.",
    },
    {
        "name": "Cross-Site Scripting",
        "level": "Medium",
        "path": "/comments",
        "tone": "warning",
        "description": "User comments rendered with '| safe' filter without HTML entity encoding.",
    },
    {
        "name": "Missing Security Headers",
        "level": "Medium",
        "path": "/",
        "tone": "warning",
        "description": "Response missing X-Content-Type-Options, X-Frame-Options, and CSP.",
    },
]

REMEDIATION_DATA = {
    "SQL Injection": {
        "name": "SQL Injection",
        "endpoint": "/search",
        "parameter": "query",
        "severity": "HIGH",
        "tone": "danger",
        "risk_of_change": "LOW",
        "risk_tone": "success",
        "file": "backend/demo_app/app.py",
        "recommended_template": "parameterized_query",
        "template_title": "Parameterized Query (Prepared Statements)",
        "explanation": "The endpoint dynamically interpolates unsanitized user input from the 'query' parameter directly into the SQL statement string. An attacker supplying SQL metacharacters (e.g., ' OR '1'='1) can alter query logic, bypass validation, or access arbitrary records.",
        "impact": "Full database read exposure, authentication bypass, data extraction, or alteration of table records depending on SQLite backend user privileges.",
        "severity_justification": "Direct SQL injection on a public search endpoint leading to unauthorized database information retrieval.",
        "diff": """--- app.py (before)
+++ app.py (after)
@@ -188,14 +188,9 @@
-    if VULN_SQLI_ENABLED:
-        # INTENTIONALLY VULNERABLE — controlled test state only, toggled via env var
-        sql = f"SELECT username, comment FROM comments WHERE comment LIKE '%{query}%'"
-        results = conn.execute(sql).fetchall()
-    else:
-        results = conn.execute(
-            "SELECT username, comment FROM comments WHERE comment LIKE ?",
-            (f"%{query}%",)
-        ).fetchall()
+    if VULN_SQLI_ENABLED:
    sql = f"SELECT username, comment FROM comments WHERE comment LIKE '%{query}%'"
    results = conn.execute(sql).fetchall()
else:
    results = conn.execute(
        "SELECT username, comment FROM comments WHERE comment LIKE ?",
        (f"%{query}%",)
    ).fetchall()
            """,
    },
    "Cross-Site Scripting": {
        "name": "Cross-Site Scripting",
        "endpoint": "/comments",
        "parameter": "comment",
        "severity": "MEDIUM",
        "tone": "warning",
        "risk_of_change": "LOW",
        "risk_tone": "success",
        "file": "backend/demo_app/templates/comments.html",
        "recommended_template": "output_encoding",
        "template_title": "Context-Aware HTML Entity Output Encoding",
        "explanation": "The Jinja2 template explicitly disables auto-escaping on user-supplied comments via the '| safe' filter. This allows stored HTML/JavaScript payloads to execute in victim client browsers when browsing the comments feed.",
        "impact": "Session cookie theft, client-side credential harvesting, DOM manipulation, or actions performed on behalf of authenticated users.",
        "severity_justification": "Stored cross-site scripting vulnerability in user-accessible comment board.",
        "diff": """--- templates/comments.html (before)
+++ templates/comments.html (after)
@@ -41,7 +41,3 @@
-                {% if vuln_xss_enabled %}
-                    {{ comment["comment"] | safe }}
-                {% else %}
-                    {{ comment["comment"] }}
-                {% endif %}
+                {{ comment["comment"] }}""",
    },
    "Missing Security Headers": {
        "name": "Missing Security Headers",
        "endpoint": "/",
        "parameter": "HTTP Response Headers",
        "severity": "MEDIUM",
        "tone": "warning",
        "risk_of_change": "LOW",
        "risk_tone": "success",
        "file": "backend/demo_app/app.py",
        "recommended_template": "add_security_header",
        "template_title": "HTTP Security Response Headers",
        "explanation": "HTTP responses do not include essential browser hardening headers: X-Content-Type-Options (nosniff), X-Frame-Options (DENY), and Content-Security-Policy (default-src 'self').",
        "impact": "Increased exposure to clickjacking, MIME-type sniffing attacks, and cross-site scripting attacks.",
        "severity_justification": "Absence of baseline web application defense-in-depth headers recommended by OWASP.",
        "diff": """--- app.py (before)
+++ app.py (after)
@@ -26,8 +26,5 @@
  @app.after_request
  def set_security_headers(response):
-    if SECURITY_HEADERS_ENABLED:
-        response.headers["X-Content-Type-Options"] = "nosniff"
-        response.headers["X-Frame-Options"] = "DENY"
-        response.headers["Content-Security-Policy"] = "default-src 'self'"
+    response.headers["X-Content-Type-Options"] = "nosniff"
+    response.headers["X-Frame-Options"] = "DENY"
+    response.headers["Content-Security-Policy"] = "default-src 'self'"
     return response""",
    },
}
@app.route("/api/scan", methods=["POST"])
def api_scan():
    try:
        findings = run_scan()
        validated = validate_all(findings)

        return jsonify({
            "status": "completed",
            "findings": validated
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500
@app.route("/api/remediation/apply", methods=["POST"])
def api_apply_remediation():
    try:
        data = request.get_json() or {}
        template_name = data.get("template")

        allowed_templates = {
            "parameterized_query",
            "output_encoding",
            "add_security_header",
        }

        if template_name not in allowed_templates:
            return jsonify({
                "status": "error",
                "message": "Invalid remediation template."
            }), 400

        result = apply_patch(template_name)

        return jsonify(result)

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500
@app.route("/")
def dashboard():
    return render_template("dashboard.html", active="dashboard", findings=findings)


@app.route("/scan")
def scan():
    return render_template("scan.html", active="scan")


@app.route("/findings")
def findings_page():
    return render_template("findings.html", active="findings", findings=findings)


@app.route("/remediation")
def remediation_page():
    finding_query = request.args.get("finding", "").strip()
    selected_finding = None
    for name, data in REMEDIATION_DATA.items():
        if finding_query.lower() == name.lower() or finding_query.lower() in name.lower():
            selected_finding = data
            break
    if not selected_finding:
        selected_finding = REMEDIATION_DATA["SQL Injection"]

    return render_template(
        "remediation.html",
        active="remediation",
        finding=selected_finding,
        all_findings=findings,
    )


VERIFICATION_CASES = {
    "VERIFIED": {
        "verdict": "VERIFIED",
        "stats": {
            "sec_passed": 3,
            "sec_total": 3,
            "func_passed": 3,
            "func_total": 3,
            "regressions": 0,
        },
        "rows": [
            {
                "name": "SQL Injection",
                "endpoint": "/search?query=...",
                "before_note": "Bypass count > control, 500 on malformed input",
                "sec_fixed": True,
                "after_note": "Prepared statement bound safely, 0 syntax error",
                "func_passed": True,
                "func_test_name": "test_search",
                "verdict": "VERIFIED",
            },
            {
                "name": "Cross-Site Scripting (XSS)",
                "endpoint": "/comments",
                "before_note": "Raw <script> executed via | safe filter",
                "sec_fixed": True,
                "after_note": "Output safely encoded via Jinja2 autoescaping",
                "func_passed": True,
                "func_test_name": "test_comments",
                "verdict": "VERIFIED",
            },
            {
                "name": "Missing Security Headers",
                "endpoint": "/",
                "before_note": "Missing nosniff, DENY, and CSP headers",
                "sec_fixed": True,
                "after_note": "X-Content-Type, X-Frame, and CSP present",
                "func_passed": True,
                "func_test_name": "test_login",
                "verdict": "VERIFIED",
            },
        ],
    },
    "REGRESSION": {
        "verdict": "REGRESSION",
        "stats": {
            "sec_passed": 3,
            "sec_total": 3,
            "func_passed": 2,
            "func_total": 3,
            "regressions": 1,
        },
        "rows": [
            {
                "name": "SQL Injection",
                "endpoint": "/search?query=...",
                "before_note": "Bypass count > control, 500 on malformed input",
                "sec_fixed": True,
                "after_note": "Security fixed, but search returned empty results",
                "func_passed": False,
                "func_test_name": "test_search",
                "verdict": "REGRESSION",
            },
            {
                "name": "Cross-Site Scripting (XSS)",
                "endpoint": "/comments",
                "before_note": "Raw <script> executed via | safe filter",
                "sec_fixed": True,
                "after_note": "Output safely encoded via Jinja2 autoescaping",
                "func_passed": True,
                "func_test_name": "test_comments",
                "verdict": "VERIFIED",
            },
            {
                "name": "Missing Security Headers",
                "endpoint": "/",
                "before_note": "Missing nosniff, DENY, and CSP headers",
                "sec_fixed": True,
                "after_note": "X-Content-Type, X-Frame, and CSP present",
                "func_passed": True,
                "func_test_name": "test_login",
                "verdict": "VERIFIED",
            },
        ],
    },
    "FAILED": {
        "verdict": "FAILED",
        "stats": {
            "sec_passed": 2,
            "sec_total": 3,
            "func_passed": 3,
            "func_total": 3,
            "regressions": 0,
        },
        "rows": [
            {
                "name": "SQL Injection",
                "endpoint": "/search?query=...",
                "before_note": "Bypass count > control, 500 on malformed input",
                "sec_fixed": False,
                "after_note": "Error signal still detected on malformed input",
                "func_passed": True,
                "func_test_name": "test_search",
                "verdict": "FAILED",
            },
            {
                "name": "Cross-Site Scripting (XSS)",
                "endpoint": "/comments",
                "before_note": "Raw <script> executed via | safe filter",
                "sec_fixed": True,
                "after_note": "Output safely encoded via Jinja2 autoescaping",
                "func_passed": True,
                "func_test_name": "test_comments",
                "verdict": "VERIFIED",
            },
            {
                "name": "Missing Security Headers",
                "endpoint": "/",
                "before_note": "Missing nosniff, DENY, and CSP headers",
                "sec_fixed": True,
                "after_note": "X-Content-Type, X-Frame, and CSP present",
                "func_passed": True,
                "func_test_name": "test_login",
                "verdict": "VERIFIED",
            },
        ],
    },
}


@app.route("/verification")
def verification_page():
    verdict_param = request.args.get("verdict", "VERIFIED").upper()
    if verdict_param not in VERIFICATION_CASES:
        verdict_param = "VERIFIED"
    case = VERIFICATION_CASES[verdict_param]
    return render_template(
        "verification.html",
        active="verification",
        verdict=case["verdict"],
        stats=case["stats"],
        rows=case["rows"],
    )


if __name__ == "__main__":
    app.run(debug=True, port=5003)