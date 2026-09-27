from scanner import check_sqli_search, check_xss_comments, check_security_headers


CHECK_FUNCTIONS = {
    "SQL Injection": check_sqli_search,
    "XSS": check_xss_comments,
    "Missing Security Headers": check_security_headers,
}


def validate_finding(finding):
    vuln_class = finding["vulnerability_class"]
    check_fn = CHECK_FUNCTIONS[vuln_class]

    recheck_finding = check_fn()

    agrees = recheck_finding["vulnerable"] == finding["vulnerable"]

    validated_finding = {
        "vulnerability_class": vuln_class,
        "endpoint": finding["endpoint"],
        "first_pass_vulnerable": finding["vulnerable"],
        "second_pass_vulnerable": recheck_finding["vulnerable"],
        "validated": agrees,
        "original_finding": finding,
    }

    return validated_finding


def validate_all(findings):
    return [validate_finding(f) for f in findings]


if __name__ == "__main__":
    from scanner import run_scan

    scan_results = run_scan()
    validated_results = validate_all(scan_results)

    for result in validated_results:
        print(result)