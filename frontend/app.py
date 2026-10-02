from flask import Flask, render_template, request, jsonify, Response
from datetime import datetime
import time
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANNER_DIR = os.path.join(PROJECT_ROOT, "backend", "scanner")

if SCANNER_DIR not in sys.path:
    sys.path.insert(0, SCANNER_DIR)

from scanner import run_scan
from validator import validate_all
from remediation import apply_patch
from scanner import (
    check_demo_sqli,
    check_demo_xss,
    check_security_headers,
)
from functionality import run_functionality_tests

app = Flask(__name__)
CURRENT_SCAN = {
    "target": None,
    "findings": [],
    "security_model": None,
    "scanned_at": None,
    "duration_seconds": None,
}
 
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
def calculate_security_score(scan_findings):
    score = 100

    penalties = {
        "SQL Injection": 20,
        "XSS": 10,
        "Cross-Site Scripting": 10,
        "Missing Security Headers": 10,
    }

    for finding in scan_findings:
        if (
            finding.get("first_pass_vulnerable") is True
            and finding.get("validated") is True
        ):
            score -= penalties.get(
                finding.get("vulnerability_class"),
                5
            )

    return max(0, min(100, score))


@app.route("/api/scan", methods=["POST"])
def api_scan():
    try:
        data = request.get_json() or {}
        target_url = data.get("target_url", "").strip()

        if not target_url:
            return jsonify({
                "status": "error",
                "message": "Target URL is required."
            }), 400

        started = time.perf_counter()

        scan_result = run_scan(target_url)

        validated = validate_all(
            scan_result["findings"],
            scan_result["target"],
        )

        duration = round(
            time.perf_counter() - started,
            1
        )

        CURRENT_SCAN["target"] = scan_result["target"]
        CURRENT_SCAN["findings"] = validated
        CURRENT_SCAN["security_model"] = scan_result["security_model"]
        CURRENT_SCAN["scanned_at"] = datetime.now().astimezone()
        CURRENT_SCAN["duration_seconds"] = duration

        return jsonify({
            "status": "completed",
            "target": scan_result["target"],
            "security_model": scan_result["security_model"],
            "findings": validated,
            "scanned_at": CURRENT_SCAN["scanned_at"].isoformat(),
            "duration_seconds": duration,
            "security_score": calculate_security_score(validated),
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

    open_findings = [
        f for f in CURRENT_SCAN["findings"]
        if f.get("first_pass_vulnerable") is True
        and f.get("validated") is True
    ]

    severity_map = {
        "SQL Injection": ("High", "danger"),
        "XSS": ("Medium", "warning"),
        "Cross-Site Scripting": ("Medium", "warning"),
        "Missing Security Headers": ("Medium", "warning"),
    }

    dashboard_findings = []

    for finding in open_findings:
        name = finding.get(
            "vulnerability_class",
            "Unknown"
        )

        level, tone = severity_map.get(
            name,
            ("Medium", "warning")
        )

        dashboard_findings.append({
            "name": (
                "Cross-Site Scripting"
                if name == "XSS"
                else name
            ),
            "level": level,
            "tone": tone,
            "path": finding.get(
                "endpoint",
                "/"
            ),
        })

    score = calculate_security_score(
        CURRENT_SCAN["findings"]
    )

    high_count = sum(
        1
        for finding in dashboard_findings
        if finding["level"] == "High"
    )

    target = CURRENT_SCAN.get("target")
    is_demo = (
        is_demo_target(target)
        if target
        else False
    )

    remediation_total = (
        3
        if is_demo
        else 0
    )

    remediation_fixed = (
        max(
            0,
            remediation_total - len(open_findings)
        )
        if remediation_total
        else 0
    )

    return render_template(
        "dashboard.html",
        active="dashboard",
        findings=dashboard_findings,
        target=target,
        score=score,
        high_count=high_count,
        scanned_at=CURRENT_SCAN.get(
            "scanned_at"
        ),
        scan_duration=CURRENT_SCAN.get(
            "duration_seconds"
        ),
        remediation_fixed=remediation_fixed,
        remediation_total=remediation_total,
    )


@app.route("/scan")
def scan():
    return render_template("scan.html", active="scan")


@app.route("/findings")
def findings_page():
    current_findings = [
        f for f in CURRENT_SCAN["findings"]
        if f.get("first_pass_vulnerable") is True
        and f.get("validated") is True
    ]
    return render_template(
        "findings.html",
        active="findings",
        findings=current_findings,
        target=CURRENT_SCAN["target"],
    )


@app.route("/remediation")
def remediation_page():

    current_findings = [
        f for f in CURRENT_SCAN["findings"]
        if f.get("first_pass_vulnerable") is True
        and f.get("validated") is True
    ]
    print("DEBUG CURRENT_SCAN FINDINGS:", CURRENT_SCAN["findings"])

    remediation_findings = []

    for f in current_findings:

        vuln_name = f["vulnerability_class"]

        remediation_key = {
            "XSS": "Cross-Site Scripting",
            "Cross-Site Scripting": "Cross-Site Scripting",
            "SQLi": "SQL Injection",
            "SQL Injection": "SQL Injection",
            "Missing Security Headers": "Missing Security Headers",
        }.get(vuln_name)

        if remediation_key:
            remediation_findings.append(
                REMEDIATION_DATA[remediation_key]
            )

    finding_query = request.args.get("finding", "").strip()

    selected_finding = None

    for data in remediation_findings:

        if finding_query.lower() == data["name"].lower():
            selected_finding = data
            break

    if selected_finding is None and remediation_findings:
        selected_finding = remediation_findings[0]

    return render_template(
        "remediation.html",
        active="remediation",
        finding=selected_finding,
        all_findings=remediation_findings,
        target=CURRENT_SCAN["target"],
    )
def is_demo_target(target):
  return target.startswith("http://127.0.0.1:5002")

def build_report_data():
    """
    Build a report from the current live scan state.

    Demo target:
        Security verification + functionality verification

    External target:
        Security assessment + remediation guidance.
        Source-level patching and functionality verification are unavailable.
    """

    target = CURRENT_SCAN.get("target")
    findings = CURRENT_SCAN.get("findings", [])

    if not target:
        return {
            "report_type": "No Scan",
            "target": None,
            "findings": [],
            "verification": {
                "status": "NOT SCANNED"
            }
        }

    vulnerable_findings = [
        f for f in findings
        if f.get("first_pass_vulnerable") is True
    ]

    # =========================================================
    # CONTROLLED DEMO REPORT
    # =========================================================

    if is_demo_target(target):

        security_rows = []

        for finding in vulnerable_findings:

            vuln_name = finding["vulnerability_class"]

            if vuln_name == "SQL Injection":
                evidence = check_demo_sqli(target)

            elif vuln_name == "XSS":
                evidence = check_demo_xss(target)

            elif vuln_name == "Missing Security Headers":
                evidence = check_security_headers(target)

            else:
                continue

            fixed = not evidence.get("vulnerable", False)

            remediation_key = {
                "XSS": "Cross-Site Scripting",
                "SQLi": "SQL Injection",
                "SQL Injection": "SQL Injection",
                "Missing Security Headers": "Missing Security Headers",
            }.get(vuln_name, vuln_name)

            security_rows.append({
                "name": vuln_name,
                "endpoint": finding.get("endpoint", "/"),
                "before": "Vulnerable",
                "after": (
                    "Security Fixed"
                    if fixed
                    else "Still Vulnerable"
                ),
                "security_fixed": fixed,
                "remediation": REMEDIATION_DATA.get(
                    remediation_key,
                    {}
                ).get(
                    "template_title",
                    "Controlled remediation template"
                ),
            })

        functionality_results = run_functionality_tests()

        sec_passed = sum(
            1
            for row in security_rows
            if row["security_fixed"]
        )

        sec_total = len(security_rows)

        func_passed = sum(
            1
            for result in functionality_results
            if result["passed"]
        )

        func_total = len(functionality_results)

        if sec_passed == sec_total and func_passed == func_total:
            verdict = "VERIFIED"

        elif sec_passed == sec_total and func_passed != func_total:
            verdict = "REGRESSION"

        else:
            verdict = "FAILED"

        return {
            "report_type": "Controlled Demo Application Report",
            "target": target,
            "findings": vulnerable_findings,

            "verification": {
                "status": verdict,
                "security_passed": sec_passed,
                "security_total": sec_total,
                "functionality_passed": func_passed,
                "functionality_total": func_total,
                "regressions": (
                    func_total - func_passed
                ),
                "security_rows": security_rows,
                "functionality_results": functionality_results,
            },

            "remediation": {
                "source_access": True,
                "patching_available": True,
                "message": (
                    "The target is the controlled SecureAI "
                    "demo application. Approved remediation "
                    "templates can be applied and verified."
                ),
            },
        }

    # =========================================================
    # EXTERNAL WEBSITE REPORT
    # =========================================================

    external_rows = []

    for finding in vulnerable_findings:

        vuln_name = finding["vulnerability_class"]

        remediation_key = {
            "XSS": "Cross-Site Scripting",
            "Cross-Site Scripting": "Cross-Site Scripting",
            "SQLi": "SQL Injection",
            "SQL Injection": "SQL Injection",
            "Missing Security Headers": "Missing Security Headers",
        }.get(vuln_name)

        remediation = REMEDIATION_DATA.get(
            remediation_key,
            {}
        )

        external_rows.append({
            "name": vuln_name,
            "endpoint": finding.get("endpoint", "/"),
            "severity": finding.get(
                "severity",
                remediation.get("severity", "UNKNOWN")
            ),
            "status": "REMEDIATION REQUIRED",
            "recommended_template": remediation.get(
                "template_title",
                "Manual remediation required"
            ),
            "source_access": False,
            "patch_applied": False,
            "reason": (
                "SecureAI does not have authorized source-code "
                "or deployment access to this external application."
            ),
        })

    return {
        "report_type": "External Website Security Assessment",
        "target": target,
        "findings": vulnerable_findings,

        "verification": {
            "status": "GUIDANCE ONLY",
            "security_verification": "LIMITED",
            "functionality_verification": "NOT AVAILABLE",
            "message": (
                "SecureAI can assess the externally accessible "
                "attack surface but cannot perform source-level "
                "remediation or application functionality "
                "verification without authorized application access."
            ),
            "security_rows": external_rows,
        },

        "remediation": {
            "source_access": False,
            "patching_available": False,
            "message": (
                "Remediation guidance has been generated. "
                "The application owner/developer must apply "
                "the required fix."
            ),
        },
    }


@app.route("/api/report")
def api_report():

    try:

        report = build_report_data()

        if not report["target"]:
            return jsonify({
                "status": "error",
                "message": "Run a scan before generating a report."
            }), 400

        target_name = (
            report["target"]
            .replace("https://", "")
            .replace("http://", "")
            .replace("/", "_")
            .replace(":", "_")
        )

        filename = f"SecureAI_Report_{target_name}.html"

        html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">

<title>SecureAI Security Report</title>

<style>

body {{
    font-family: Arial, sans-serif;
    margin: 40px;
    color: #222;
    line-height: 1.5;
}}

h1 {{
    margin-bottom: 5px;
}}

h2 {{
    margin-top: 30px;
    border-bottom: 1px solid #ddd;
    padding-bottom: 6px;
}}

.badge {{
    display: inline-block;
    padding: 6px 12px;
    border-radius: 5px;
    background: #eee;
    font-weight: bold;
}}

.success {{
    color: #087f23;
}}

.warning {{
    color: #9a6700;
}}

.danger {{
    color: #b42318;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
}}

th,
td {{
    border: 1px solid #ddd;
    padding: 10px;
    text-align: left;
    vertical-align: top;
}}

th {{
    background: #f5f5f5;
}}

.small {{
    color: #666;
    font-size: 13px;
}}

</style>

</head>

<body>

<h1>SecureAI Security Report</h1>

<p>
<strong>Report Type:</strong>
{report["report_type"]}
</p>

<p>
<strong>Target:</strong>
{report["target"]}
</p>

<h2>Executive Summary</h2>

<p>
This report was generated automatically by SecureAI
from the current scan state.
</p>

<p>
<strong>Final Status:</strong>
<span class="badge">
{report["verification"]["status"]}
</span>
</p>

<h2>Findings</h2>
"""

        if report["findings"]:

            html += """
<table>

<tr>
<th>Vulnerability</th>
<th>Endpoint</th>
<th>Severity</th>
<th>Validated</th>
</tr>
"""

            for finding in report["findings"]:

                severity = finding.get(
                    "severity",
                    "Not specified"
                )

                validated = finding.get(
                    "validated",
                    False
                )

                html += f"""
<tr>

<td>
{finding.get("vulnerability_class", "Unknown")}
</td>

<td>
{finding.get("endpoint", "/")}
</td>

<td>
{severity}
</td>

<td>
{"Yes" if validated else "No"}
</td>

</tr>
"""

            html += """
</table>
"""

        else:

            html += """
<p>
No supported vulnerabilities were present
in the current scan findings.
</p>
"""

        html += """
<h2>Remediation</h2>
"""

        if report["remediation"]["source_access"]:

            html += """
<p class="success">

<strong>Source access:</strong>
Available for the controlled demo application.

</p>

<p>
Approved remediation templates can be applied to the
demo application's source code and subsequently verified.
</p>
"""

        else:

            html += """
<p class="warning">

<strong>Source access:</strong>
Not available.

</p>

<p>
<strong>Patch applied:</strong>
No
</p>

<p>
<strong>Reason:</strong>
SecureAI does not have authorized source-code or
deployment access to this external application.
</p>

<p>
The report therefore provides remediation guidance only.
The application owner or authorized developer must apply
the recommended changes.
</p>
"""

        html += """
<h2>Verification</h2>
"""

        if report["report_type"] == "Controlled Demo Application Report":

            verification = report["verification"]

            html += f"""
<table>

<tr>
<th>Security Checks</th>
<th>Functionality Tests</th>
<th>Regressions</th>
<th>Final Verdict</th>
</tr>

<tr>

<td>
{verification["security_passed"]}/
{verification["security_total"]}
</td>

<td>
{verification["functionality_passed"]}/
{verification["functionality_total"]}
</td>

<td>
{verification["regressions"]}
</td>

<td>
{verification["status"]}
</td>

</tr>

</table>
"""

        else:

            html += """
<p class="warning">

<strong>Security verification:</strong>
Limited to externally observable behavior.

</p>

<p class="warning">

<strong>Functionality verification:</strong>
Not available because SecureAI does not have
authorized application-level access.

</p>

<p>
<strong>Patch verification:</strong>
Pending application-owner remediation.
</p>
"""

        html += """

<h2>Security Engineering Boundary</h2>

<p class="small">

SecureAI is designed for controlled and authorized
security assessment. External websites are assessed
only through their accessible behavior.

SecureAI does not claim to modify arbitrary external
applications without authorized source-code or
deployment access.

</p>

<p class="small">
Generated by SecureAI.
</p>

</body>
</html>
"""

        return Response(
            html,
            mimetype="text/html",
            headers={
                "Content-Disposition": (
                    f"attachment; filename={filename}"
                )
            }
        )

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route("/verification")
def verification_page():

    if not CURRENT_SCAN["target"]:

        functionality_results = [
            {
                "test": "login",
                "passed": False,
                "status_code": 0
            },
            {
                "test": "search",
                "passed": False,
                "status_code": 0
            },
            {
                "test": "comments",
                "passed": False,
                "status_code": 0
            },
        ]

        return render_template(
            "verification.html",
            active="verification",
            verdict="NOT SCANNED",
            stats={
                "sec_passed": 0,
                "sec_total": 0,
                "func_passed": 0,
                "func_total": 0,
                "regressions": 0,
            },
            rows=[],
            functionality_results=functionality_results,
            target=None,
            is_external=False,
        )

    target = CURRENT_SCAN["target"]

    # =========================================================
    # CONTROLLED DEMO APPLICATION
    # =========================================================

    if is_demo_target(target):

        security_checks = [
            ("SQL Injection", check_demo_sqli),
            ("XSS", check_demo_xss),
            ("Missing Security Headers", check_security_headers),
        ]

        rows = []
        sec_passed = 0

        for name, check_fn in security_checks:

            evidence = check_fn(target)

            security_fixed = not evidence.get(
                "vulnerable",
                False
            )

            if security_fixed:
                sec_passed += 1

            rows.append({
                "name": name,
                "endpoint": evidence.get(
                    "endpoint",
                    "/"
                ),
                "before_note": (
                    "Detected during initial security scan"
                ),
                "sec_fixed": security_fixed,
                "after_note": (
                    "Security check passed"
                    if security_fixed
                    else "Vulnerability still detected"
                ),
                "func_passed": True,
                "func_test_name": "Security verification",
                "verdict": (
                    "VERIFIED"
                    if security_fixed
                    else "FAILED"
                ),
            })

        security_total = len(security_checks)

        functionality_results = run_functionality_tests()

        if not functionality_results:

            functionality_results = [
                {
                    "test": "login",
                    "passed": False,
                    "status_code": 0
                },
                {
                    "test": "search",
                    "passed": False,
                    "status_code": 0
                },
                {
                    "test": "comments",
                    "passed": False,
                    "status_code": 0
                },
            ]

        func_passed = sum(
            1
            for result in functionality_results
            if result["passed"]
        )

        func_total = len(functionality_results)

        all_security_fixed = (
            sec_passed == security_total
        )

        all_functionality_passed = (
            func_passed == func_total
        )

        if (
            all_security_fixed
            and all_functionality_passed
        ):
            verdict = "VERIFIED"

        elif (
            all_security_fixed
            and not all_functionality_passed
        ):
            verdict = "REGRESSION"

        else:
            verdict = "FAILED"

        stats = {
            "sec_passed": sec_passed,
            "sec_total": security_total,
            "func_passed": func_passed,
            "func_total": func_total,
            "regressions": (
                func_total - func_passed
            ),
        }

        return render_template(
            "verification.html",
            active="verification",
            verdict=verdict,
            stats=stats,
            rows=rows,
            target=target,
            functionality_results=functionality_results,
            is_external=False,
        )

    # =========================================================
    # EXTERNAL WEBSITE
    # =========================================================

    rows = []

    vulnerable_findings = [
        f
        for f in CURRENT_SCAN["findings"]
        if f.get("first_pass_vulnerable") is True
    ]

    for finding in vulnerable_findings:

        rows.append({
            "name": finding["vulnerability_class"],
            "endpoint": finding.get("endpoint", "/"),
            "before_note": (
                "Finding detected during external "
                "security assessment"
            ),
            "sec_fixed": False,
            "after_note": (
                "Source-level remediation unavailable"
            ),
            "func_passed": False,
            "func_test_name": (
                "Not available — external source "
                "access unavailable"
            ),
            "verdict": "GUIDANCE ONLY",
        })

    security_total = len(rows)

    functionality_results = []

    stats = {
        "sec_passed": 0,
        "sec_total": security_total,
        "func_passed": 0,
        "func_total": 0,
        "regressions": 0,
    }

    return render_template(
        "verification.html",
        active="verification",
        verdict="GUIDANCE ONLY",
        stats=stats,
        rows=rows,
        target=target,
        functionality_results=functionality_results,
        is_external=True,
    )


if __name__ == "__main__":
    app.run(debug=True, port=5003)