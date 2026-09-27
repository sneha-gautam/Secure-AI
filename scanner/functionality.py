import requests
import random
import string

TARGET_BASE_URL = "http://127.0.0.1:5002"


def test_login():
    session = requests.Session()
    resp = session.post(
        f"{TARGET_BASE_URL}/login",
        data={"username": "admin", "password": "Admin@123"}
    )
    passed = "Login successful" in resp.text
    return {"test": "login", "passed": passed, "status_code": resp.status_code}


def test_search():
    resp = requests.get(
        f"{TARGET_BASE_URL}/search",
        params={"query": "Security"}
    )
    passed = "Security testing is important" in resp.text
    return {"test": "search", "passed": passed, "status_code": resp.status_code}


def test_comments():
    session = requests.Session()
    session.post(
        f"{TARGET_BASE_URL}/login",
        data={"username": "admin", "password": "Admin@123"}
    )

    marker = "".join(random.choices(string.ascii_lowercase, k=8))
    comment_text = f"functionality-test-{marker}"

    session.post(f"{TARGET_BASE_URL}/comments", data={"comment": comment_text})
    resp = session.get(f"{TARGET_BASE_URL}/comments")

    passed = comment_text in resp.text
    return {"test": "comments", "passed": passed, "status_code": resp.status_code}


def run_functionality_tests():
    return [test_login(), test_search(), test_comments()]


def functionality_verified(results):
    return all(result["passed"] for result in results)


if __name__ == "__main__":
    results = run_functionality_tests()

    for result in results:
        status = "PASSED" if result["passed"] else "FAILED"
        print(f"{result['test']}: {status}")

    overall = functionality_verified(results)
    print(f"\nOverall functionality verified: {overall}")