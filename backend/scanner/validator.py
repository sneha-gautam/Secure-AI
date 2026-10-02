import sys
import os


SCANNER_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

if SCANNER_DIR not in sys.path:
    sys.path.insert(0, SCANNER_DIR)

from scanner import (
    run_scan,
    check_demo_sqli,
    check_demo_xss,
    check_security_headers,
    is_demo_target,
)


def validate_finding(
    finding,
    target_url,
):
    """
    Re-run the relevant security check against the
    same target and compare the result with the
    first-pass finding.

    This is consistency validation, not an independent
    scanner engine.
    """

    vuln_class = finding[
        "vulnerability_class"
    ]

    # ---------------------------------------------------------
    # Controlled SecureAI demo
    # ---------------------------------------------------------

    if is_demo_target(target_url):

        if vuln_class == "SQL Injection":
            recheck_finding = check_demo_sqli(
                target_url
            )

        elif vuln_class == "XSS":
            recheck_finding = check_demo_xss(
                target_url
            )

        elif vuln_class == "Missing Security Headers":
            recheck_finding = check_security_headers(
                target_url
            )

        else:
            raise ValueError(
                f"Unsupported vulnerability class: "
                f"{vuln_class}"
            )

    # ---------------------------------------------------------
    # External target
    # ---------------------------------------------------------

    else:

        # For external targets, obtain a fresh scan and
        # locate the corresponding vulnerability class/
        # endpoint/parameter.
        fresh_scan = run_scan(
            target_url
        )

        matching_findings = [
            item
            for item in fresh_scan["findings"]
            if (
                item["vulnerability_class"]
                == vuln_class
                and item.get("endpoint")
                == finding.get("endpoint")
                and item.get("parameter")
                == finding.get("parameter")
            )
        ]

        if matching_findings:
            recheck_finding = matching_findings[0]
        else:
            recheck_finding = {
                "vulnerable": False,
                "recheck_available": False,
            }

    agrees = (
        recheck_finding["vulnerable"]
        == finding["vulnerable"]
    )

    validated_finding = {
        "vulnerability_class": vuln_class,
        "endpoint": finding.get(
            "endpoint"
        ),
        "parameter": finding.get(
            "parameter"
        ),
        "first_pass_vulnerable": finding[
            "vulnerable"
        ],
        "second_pass_vulnerable": recheck_finding[
            "vulnerable"
        ],
        "validated": agrees,
        "original_finding": finding,
        "recheck_finding": recheck_finding,
    }

    return validated_finding


def validate_all(
    findings,
    target_url,
):
    return [
        validate_finding(
            finding,
            target_url,
        )
        for finding in findings
    ]


if __name__ == "__main__":

    target = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "http://127.0.0.1:5002"
    )

    scan_result = run_scan(
        target
    )

    validated_results = validate_all(
        scan_result["findings"],
        scan_result["target"],
    )

    for result in validated_results:
        print(result)