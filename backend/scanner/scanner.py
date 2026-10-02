import requests
import random
import string
import sys
import os

# Import the Security Model Builder
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "security_model"))
from security_model import build_security_model

# security_model.py's own sys.path.insert (for importing demo_app) runs
# automatically when the line above executes, so demo_app is importable now.
from app import app as demo_app

MODEL = build_security_model(demo_app, base_url="http://127.0.0.1:5002")
TARGET_BASE_URL = MODEL["base_url"]


def get_route(path):
    for route in MODEL["routes"]:
        if route["path"] == path:
            return route
    return None


def require_input(path, input_name):
    """Confirms the Security Model actually knows about this endpoint/input
    before the scanner runs a hardcoded check against it."""
    route = get_route(path)
    if route is None:
        raise RuntimeError(f"Security Model has no record of route '{path}'")
    if input_name not in route.get("inputs", []):
        raise RuntimeError(
            f"Security Model does not list '{input_name}' as an input on '{path}'"
        )


def check_sqli_search():
    require_input("/search", "query")

    control_word = "Security"
    bypass_payload = "' OR '1'='1"
    malformed_payload = "'"

    control_resp = requests.get(f"{TARGET_BASE_URL}/search", params={"query": control_word})
    bypass_resp = requests.get(f"{TARGET_BASE_URL}/search", params={"query": bypass_payload})
    malformed_resp = requests.get(f"{TARGET_BASE_URL}/search", params={"query": malformed_payload})

    control_count = control_resp.text.count("<li>")
    bypass_count = bypass_resp.text.count("<li>")

    bypass_signal = bypass_count > control_count
    error_signal = malformed_resp.status_code == 500

    finding = {
        "endpoint": "/search",
        "parameter": "query",
        "vulnerability_class": "SQL Injection",
        "bypass_signal": bypass_signal,
        "error_signal": error_signal,
        "vulnerable": bypass_signal or error_signal,
        "control_count": control_count,
        "bypass_count": bypass_count,
        "malformed_status_code": malformed_resp.status_code,
    }

    return finding


def check_xss_comments():
    require_input("/comments", "comment")

    session = requests.Session()

    login_resp = session.post(
        f"{TARGET_BASE_URL}/login",
        data={"username": "admin", "password": "Admin@123"}
    )

    marker = "".join(random.choices(string.ascii_lowercase, k=8))
    payload = f"<script>alert('XSS-{marker}')</script>"

    session.post(f"{TARGET_BASE_URL}/comments", data={"comment": payload})

    comments_resp = session.get(f"{TARGET_BASE_URL}/comments")

    unescaped_found = payload in comments_resp.text

    finding = {
        "endpoint": "/comments",
        "parameter": "comment",
        "vulnerability_class": "XSS",
        "login_status_code": login_resp.status_code,
        "unescaped_found": unescaped_found,
        "vulnerable": unescaped_found,
    }

    return finding


def check_security_headers():
    route = get_route("/")
    if route is None:
        raise RuntimeError("Security Model has no record of route '/'")

    resp = requests.get(f"{TARGET_BASE_URL}/")

    required_headers = [
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Content-Security-Policy",
    ]

    missing_headers = [h for h in required_headers if h not in resp.headers]

    finding = {
        "endpoint": "/",
        "vulnerability_class": "Missing Security Headers",
        "checked_headers": required_headers,
        "missing_headers": missing_headers,
        "vulnerable": len(missing_headers) > 0,
    }

    return finding


def run_scan():
    findings = [
        check_sqli_search(),
        check_xss_comments(),
        check_security_headers(),
    ]
    return findings


if __name__ == "__main__":
    print(f"Using Security Model — base_url: {TARGET_BASE_URL}, routes discovered: {len(MODEL['routes'])}\n")
    results = run_scan()
    for finding in results:
        print(finding)