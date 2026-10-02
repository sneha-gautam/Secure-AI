import random
import string
import sys
import os
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests


REQUEST_TIMEOUT = 8


# Allow importing the centralized Security Model.
SECURITY_MODEL_DIR = os.path.join(
    os.path.dirname(__file__),
    "..",
    "security_model",
)

if SECURITY_MODEL_DIR not in sys.path:
    sys.path.insert(0, SECURITY_MODEL_DIR)

from security_model import build_security_model


def normalize_url(url):
    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path or "/",
        "",
        parsed.query,
        "",
    ))


def is_demo_target(target_url):
    parsed = urlparse(normalize_url(target_url))

    return (
        parsed.hostname in ("127.0.0.1", "localhost")
        and parsed.port == 5002
    )


def get_parameter_url(parameter):
    return parameter["url"]


def check_demo_sqli(target_url):
    """
    High-confidence SQL Injection check for the controlled
    SecureAI demo application.
    """

    base = normalize_url(target_url).rstrip("/")

    control_word = "Security"
    bypass_payload = "' OR '1'='1"
    malformed_payload = "'"

    control_resp = requests.get(
        f"{base}/search",
        params={"query": control_word},
        timeout=REQUEST_TIMEOUT,
    )

    bypass_resp = requests.get(
        f"{base}/search",
        params={"query": bypass_payload},
        timeout=REQUEST_TIMEOUT,
    )

    malformed_resp = requests.get(
        f"{base}/search",
        params={"query": malformed_payload},
        timeout=REQUEST_TIMEOUT,
    )

    control_count = control_resp.text.count("<li>")
    bypass_count = bypass_resp.text.count("<li>")

    bypass_signal = bypass_count > control_count
    error_signal = malformed_resp.status_code == 500

    return {
        "endpoint": "/search",
        "parameter": "query",
        "vulnerability_class": "SQL Injection",
        "bypass_signal": bypass_signal,
        "error_signal": error_signal,
        "vulnerable": bypass_signal or error_signal,
        "control_count": control_count,
        "bypass_count": bypass_count,
        "malformed_status_code": malformed_resp.status_code,
        "evidence": (
            "Controlled comparison showed a materially larger result "
            "set for the SQL injection test payload."
        ),
    }


def check_demo_xss(target_url):
    """
    High-confidence XSS check for the controlled
    SecureAI demo application.
    """

    base = normalize_url(target_url).rstrip("/")

    session = requests.Session()

    login_resp = session.post(
        f"{base}/login",
        data={
            "username": "admin",
            "password": "Admin@123",
        },
        timeout=REQUEST_TIMEOUT,
    )

    marker = "".join(
        random.choices(string.ascii_lowercase, k=8)
    )

    payload = (
        f"<script>alert('XSS-{marker}')</script>"
    )

    session.post(
        f"{base}/comments",
        data={"comment": payload},
        timeout=REQUEST_TIMEOUT,
    )

    comments_resp = session.get(
        f"{base}/comments",
        timeout=REQUEST_TIMEOUT,
    )

    unescaped_found = payload in comments_resp.text

    return {
        "endpoint": "/comments",
        "parameter": "comment",
        "vulnerability_class": "XSS",
        "login_status_code": login_resp.status_code,
        "unescaped_found": unescaped_found,
        "vulnerable": unescaped_found,
        "evidence": (
            "A controlled HTML script payload was returned unescaped "
            "in the comments response."
        ),
        "execution_verified": False,
    }


def check_generic_xss(parameter):
    """
    Conservative reflection-based XSS indicator.

    A positive result means the unique marker was reflected in the
    response without establishing browser execution.
    """

    parsed = urlparse(
        get_parameter_url(parameter)
    )

    marker = (
        "SecureAI_XSS_"
        + "".join(
            random.choices(
                string.ascii_lowercase,
                k=8,
            )
        )
    )

    query = dict(
        parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )
    )

    query[parameter["parameter"]] = marker

    test_url = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path or "/",
        "",
        urlencode(query),
        "",
    ))

    try:
        response = requests.get(
            test_url,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException:
        return None

    reflected = marker in response.text

    if not reflected:
        return None

    return {
        "endpoint": parsed.path or "/",
        "parameter": parameter["parameter"],
        "vulnerability_class": "XSS",
        "reflection_signal": True,
        "vulnerable": True,
        "evidence": (
            "A unique marker was reflected in the HTTP response."
        ),
        "execution_verified": False,
    }


def check_generic_sqli(parameter):
    """
    Conservative SQL error-based indicator.

    A positive result means a database/SQL error signature was
    observed after a controlled quote mutation. It does not claim
    full SQL injection exploitation.
    """

    parsed = urlparse(
        get_parameter_url(parameter)
    )

    original_value = parameter.get("value") or "1"

    query = dict(
        parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )
    )

    control_query = dict(query)
    control_query[
        parameter["parameter"]
    ] = original_value

    test_query = dict(query)
    test_query[
        parameter["parameter"]
    ] = original_value + "'"

    control_url = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path or "/",
        "",
        urlencode(control_query),
        "",
    ))

    test_url = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path or "/",
        "",
        urlencode(test_query),
        "",
    ))

    try:
        control_resp = requests.get(
            control_url,
            timeout=REQUEST_TIMEOUT,
        )

        test_resp = requests.get(
            test_url,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException:
        return None

    sql_error_terms = [
        "sql syntax",
        "sqlite error",
        "mysql",
        "postgresql",
        "syntax error",
        "database error",
        "unclosed quotation",
    ]

    body = test_resp.text.lower()

    error_signal = (
        test_resp.status_code >= 500
        and any(
            term in body
            for term in sql_error_terms
        )
    )

    if not error_signal:
        return None

    return {
        "endpoint": parsed.path or "/",
        "parameter": parameter["parameter"],
        "vulnerability_class": "SQL Injection",
        "error_signal": True,
        "control_status_code": control_resp.status_code,
        "test_status_code": test_resp.status_code,
        "vulnerable": True,
        "evidence": (
            "A database/SQL error signature was observed after "
            "a controlled quote mutation."
        ),
    }


def check_security_headers(target_url):
    """
    Check the target's main response for the required
    baseline security headers.
    """

    target_url = normalize_url(target_url)

    response = requests.get(
        target_url,
        timeout=REQUEST_TIMEOUT,
    )

    required_headers = [
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Content-Security-Policy",
    ]

    missing_headers = [
        header
        for header in required_headers
        if header not in response.headers
    ]

    return {
        "endpoint": (
            urlparse(response.url).path
            or "/"
        ),
        "vulnerability_class": "Missing Security Headers",
        "checked_headers": required_headers,
        "missing_headers": missing_headers,
        "vulnerable": len(missing_headers) > 0,
    }


def run_scan(target_url):
    """
    Target-aware DAST scan.

    1. Build the Security Model for the supplied target.
    2. Use controlled high-confidence checks for the SecureAI demo.
    3. Use conservative discovery-based checks for other targets.
    """

    target_url = normalize_url(target_url)

    model = build_security_model(
        target_url
    )

    findings = []

    # ---------------------------------------------------------
    # Controlled SecureAI demo
    # ---------------------------------------------------------

    if is_demo_target(target_url):

        findings.append(
            check_demo_sqli(target_url)
        )

        findings.append(
            check_demo_xss(target_url)
        )

        findings.append(
            check_security_headers(target_url)
        )

    # ---------------------------------------------------------
    # External / authorized target
    # ---------------------------------------------------------

    else:

        for parameter in model.get(
            "parameters",
            [],
        ):
            finding = check_generic_sqli(
                parameter
            )

            if finding:
                findings.append(finding)

        for parameter in model.get(
            "parameters",
            [],
        ):
            finding = check_generic_xss(
                parameter
            )

            if finding:
                findings.append(finding)

        findings.append(
            check_security_headers(
                target_url
            )
        )

    return {
        "target": target_url,
        "security_model": model,
        "findings": findings,
    }


if __name__ == "__main__":

    target = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "http://127.0.0.1:5002"
    )

    result = run_scan(target)

    print(
        f"Target: {result['target']}"
    )

    print(
        "Pages discovered: "
        f"{len(result['security_model'].get('pages', []))}"
    )

    print(
        "Parameters discovered: "
        f"{len(result['security_model'].get('parameters', []))}"
    )

    print(
        "Forms discovered: "
        f"{len(result['security_model'].get('forms', []))}"
    )

    print("\nFindings:")

    for finding in result["findings"]:
        print(finding)