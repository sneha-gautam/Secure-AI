from verification import verify_all
from functionality import run_functionality_tests, functionality_verified


def compute_verdict(security_result, functionality_passed):
    security_fixed = security_result["security_verified"]

    if security_fixed and functionality_passed:
        verdict = "VERIFIED"
    elif security_fixed and not functionality_passed:
        verdict = "REGRESSION"
    else:
        verdict = "FAILED"

    return {
        "vulnerability_class": security_result["vulnerability_class"],
        "security_fixed": security_fixed,
        "functionality_passed": functionality_passed,
        "verdict": verdict,
    }


def run_final_verdict():
    vuln_classes = ["SQL Injection", "XSS", "Missing Security Headers"]

    security_results = verify_all(vuln_classes)

    functionality_results = run_functionality_tests()
    overall_functionality_passed = functionality_verified(functionality_results)

    final_verdicts = [
        compute_verdict(sec_result, overall_functionality_passed)
        for sec_result in security_results
    ]

    return final_verdicts


if __name__ == "__main__":
    verdicts = run_final_verdict()

    for v in verdicts:
        print(
            f"{v['vulnerability_class']}: {v['verdict']} "
            f"(security_fixed={v['security_fixed']}, "
            f"functionality_passed={v['functionality_passed']})"
        )