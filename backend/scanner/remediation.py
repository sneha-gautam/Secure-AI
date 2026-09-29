import difflib
import os
import shutil

REMEDIATION_TEMPLATES = {
    "parameterized_query": {
        "file": "app.py",
        "before": '''    if VULN_SQLI_ENABLED:
        # INTENTIONALLY VULNERABLE — controlled test state only, toggled via env var
        sql = f"SELECT username, comment FROM comments WHERE comment LIKE '%{query}%'"
        results = conn.execute(sql).fetchall()
    else:
        results = conn.execute(
            "SELECT username, comment FROM comments WHERE comment LIKE ?",
            (f"%{query}%",)
        ).fetchall()
''',
        "after": '''    results = conn.execute(
        "SELECT username, comment FROM comments WHERE comment LIKE ?",
        (f"%{query}%",)
    ).fetchall()
''',
    },
    "add_security_header": {
        "file": "app.py",
        "before": '''@app.after_request
def set_security_headers(response):
    if SECURITY_HEADERS_ENABLED:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response
''',
        "after": '''@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response
''',
    },
    "output_encoding": {
        "file": "templates/comments.html",
        "before": '''                {% if vuln_xss_enabled %}
                    {{ comment["comment"] | safe }}
                {% else %}
                    {{ comment["comment"] }}
                {% endif %}
''',
        "after": '''                {{ comment["comment"] }}
''',
    }
}

DEMO_APP_DIR = os.path.join(os.path.dirname(__file__), "..", "demo_app")


def generate_diff(template_name):
    template = REMEDIATION_TEMPLATES[template_name]
    before_lines = template["before"].splitlines(keepends=True)
    after_lines = template["after"].splitlines(keepends=True)

    diff_lines = difflib.unified_diff(
        before_lines,
        after_lines,
        fromfile=f"{template['file']} (before)",
        tofile=f"{template['file']} (after)",
        lineterm=""
    )

    return "\n".join(diff_lines)


def get_human_decision(remediation):
    print(f"\nProposed remediation: {remediation['template']}")
    print(remediation['diff'])
    print()

    decision = input("Approve this remediation? (yes/no): ").strip().lower()

    if decision == "yes":
        return "APPROVED"
    else:
        return "REJECTED"


def backup_file(target_path):
    backup_path = target_path + ".bak"

    if not os.path.exists(backup_path):
        shutil.copy(target_path, backup_path)
        print(f"Backup created: {backup_path}")
    else:
        print(f"Backup already exists, not overwriting: {backup_path}")

    return backup_path


def apply_patch(template_name):
    template = REMEDIATION_TEMPLATES[template_name]
    target_path = os.path.join(DEMO_APP_DIR, template["file"])

    backup_file(target_path)

    with open(target_path, "r") as f:
        content = f.read()

    if template["before"] not in content:
        return {
            "status": "APPLY_FAILED",
            "reason": "before-text not found in target file (already patched, or file changed)",
        }

    new_content = content.replace(template["before"], template["after"], 1)

    with open(target_path, "w") as f:
        f.write(new_content)

    return {
        "status": "APPLIED",
        "file": target_path,
    }


def rollback_patch(template_name):
    if template_name not in REMEDIATION_TEMPLATES:
        return {
            "status": "ROLLBACK_FAILED",
            "reason": f"Unknown template: {template_name}",
        }

    template = REMEDIATION_TEMPLATES[template_name]
    target_path = os.path.join(DEMO_APP_DIR, template["file"])
    backup_path = target_path + ".bak"

    if not os.path.exists(backup_path):
        return {
            "status": "ROLLBACK_FAILED",
            "reason": f"Backup file does not exist: {backup_path}",
            "file": target_path,
        }

    try:
        shutil.copy(backup_path, target_path)
        return {
            "status": "ROLLED_BACK",
            "file": target_path,
        }
    except Exception as e:
        return {
            "status": "ROLLBACK_FAILED",
            "reason": str(e),
            "file": target_path,
        }


def prepare_remediation(analysis_result):
    template_name = analysis_result["recommended_template"]

    if template_name not in REMEDIATION_TEMPLATES:
        return {
            "template": template_name,
            "diff": None,
            "status": "NO_TEMPLATE_AVAILABLE",
        }

    diff_text = generate_diff(template_name)

    remediation = {
        "template": template_name,
        "diff": diff_text,
        "status": "PENDING_APPROVAL",
    }

    decision = get_human_decision(remediation)
    remediation["status"] = decision

    if decision == "APPROVED":
        apply_result = apply_patch(template_name)
        remediation["apply_result"] = apply_result

    return remediation


if __name__ == "__main__":
    from scanner import run_scan
    from validator import validate_all
    from ai_analysis import analyze_all

    scan_results = run_scan()
    validated_results = validate_all(scan_results)
    analysis_results = analyze_all(validated_results)

    for analysis in analysis_results:
        remediation = prepare_remediation(analysis)
        print(f"\nFinal decision for {remediation['template']}: {remediation['status']}")
        if "apply_result" in remediation:
            print(f"Apply result: {remediation['apply_result']}")
        print("=" * 50)