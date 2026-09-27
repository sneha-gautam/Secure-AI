from scanner import check_sqli_search, check_xss_comments, check_security_headers

VERIFICATION_CHECKS = {
    "SQL Injection": check_sqli_search,
    "XSS": check_xss_comments,
    "Missing Security Headers": check_security_headers,
}


def verify_security(vulnerability_class):
    check_fn = VERIFICATION_CHECKS[vulnerability_class]
    evidence = check_fn()

    return {
        "vulnerability_class": vulnerability_class,
        "security_verified": not evidence["vulnerable"],
        "evidence": evidence,
    }


def verify_all(vulnerability_classes):
    return [verify_security(vc) for vc in vulnerability_classes]


if __name__ == "__main__":
    classes = ["SQL Injection", "XSS", "Missing Security Headers"]
    results = verify_all(classes)

    for result in results:
        status = "VERIFIED" if result["security_verified"] else "NOT FIXED"
        print(f"{result['vulnerability_class']}: {status}")
        print(f"  evidence: {result['evidence']}")
        print()