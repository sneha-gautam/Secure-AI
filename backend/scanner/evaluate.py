#!/usr/bin/env python3
"""
SecureAI — Evaluation Metrics Script
------------------------------------
This script evaluates the SecureAI vulnerability verification and remediation pipeline
against the demo application across a configurable number of runs (default: 10).

Metrics evaluated:
1. Detection accuracy:
   Fraction of known-vulnerable ground-truth cases correctly flagged (vulnerable=True).
2. False positive rate:
   Fraction of safe ground-truth cases incorrectly flagged (vulnerable=True).
3. Verification accuracy:
   Fraction of applied patches correctly verified as safe (security_verified=True).
4. Regression detection rate:
   Fraction of deliberately broken patches correctly caught as REGRESSION and rolled back.
5. End-to-end pipeline time:
   Average wall-clock time for the complete automated workflow
   (Scan -> Validate -> AI Analysis -> Remediation Patch -> Verification -> Functionality -> Final Verdict).
"""

import argparse
import contextlib
import os
import shutil
import subprocess
import sys
import time
import requests

# Ensure scanner directory is in sys.path
SCANNER_DIR = os.path.dirname(os.path.abspath(__file__))
if SCANNER_DIR not in sys.path:
    sys.path.insert(0, SCANNER_DIR)

from scanner import run_scan
from validator import validate_all
from ai_analysis import analyze_all, TEMPLATE_MAP
from remediation import apply_patch, rollback_patch, REMEDIATION_TEMPLATES, DEMO_APP_DIR
from verification import verify_all
from functionality import run_functionality_tests, functionality_verified
from final_verdict import run_final_verdict

VULNERABLE_ENV = {
    "VULN_SQLI_ENABLED": "true",
    "VULN_XSS_ENABLED": "true",
    "SECURITY_HEADERS_ENABLED": "false",
}

SAFE_ENV = {
    "VULN_SQLI_ENABLED": "false",
    "VULN_XSS_ENABLED": "false",
    "SECURITY_HEADERS_ENABLED": "true",
}

ALL_VULN_CLASSES = ["SQL Injection", "XSS", "Missing Security Headers"]


def kill_port_5002():
    """Kills any process currently listening on port 5002."""
    try:
        out = subprocess.check_output(["lsof", "-t", "-i", ":5002"], text=True)
        for pid_str in out.strip().split():
            try:
                os.kill(int(pid_str), 9)
            except Exception:
                pass
    except Exception:
        pass


def restore_pristine_files():
    """Restores app.py and templates/comments.html from .bak files if available."""
    app_bak = os.path.join(DEMO_APP_DIR, "app.py.bak")
    app_live = os.path.join(DEMO_APP_DIR, "app.py")
    if os.path.exists(app_bak):
        shutil.copy(app_bak, app_live)

    comments_bak = os.path.join(DEMO_APP_DIR, "templates", "comments.html.bak")
    comments_live = os.path.join(DEMO_APP_DIR, "templates", "comments.html")
    if os.path.exists(comments_bak):
        shutil.copy(comments_bak, comments_live)


@contextlib.contextmanager
def run_demo_app(env_vars):
    """Context manager to spawn the demo Flask app with specific environment variables,
    wait for healthcheck, and cleanly shut down on exit.
    """
    kill_port_5002()

    env = os.environ.copy()
    env.update(env_vars)

    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import app; app.init_db(); app.seed_users(); app.seed_comments(); app.app.run(port=5002, debug=False)",
        ],
        cwd=DEMO_APP_DIR,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        ready = False
        start_wait = time.time()
        while time.time() - start_wait < 5.0:
            try:
                r = requests.get("http://127.0.0.1:5002/health", timeout=0.5)
                if r.status_code == 200:
                    ready = True
                    break
            except Exception:
                time.sleep(0.05)

        if not ready:
            raise RuntimeError("Demo app failed to respond on http://127.0.0.1:5002/health within 5s.")

        yield proc
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            proc.kill()
        kill_port_5002()


def evaluate_detection_accuracy(num_runs):
    """Evaluates detection accuracy across num_runs with vulnerabilities enabled."""
    total_expected = len(ALL_VULN_CLASSES) * num_runs
    detected_count = 0

    for _ in range(num_runs):
        restore_pristine_files()
        with run_demo_app(VULNERABLE_ENV):
            findings = run_scan()
            for f in findings:
                if f.get("vulnerable") is True:
                    detected_count += 1

    return detected_count, total_expected


def evaluate_false_positive_rate(num_runs):
    """Evaluates false positive rate across num_runs with safe environment flags."""
    total_safe_checks = len(ALL_VULN_CLASSES) * num_runs
    false_positives = 0

    for _ in range(num_runs):
        restore_pristine_files()
        with run_demo_app(SAFE_ENV):
            findings = run_scan()
            for f in findings:
                if f.get("vulnerable") is True:
                    false_positives += 1

    return false_positives, total_safe_checks


def evaluate_verification_accuracy(num_runs):
    """Applies official remediation patches and evaluates verification accuracy."""
    total_patches = len(ALL_VULN_CLASSES) * num_runs
    verified_count = 0

    for _ in range(num_runs):
        restore_pristine_files()
        # Apply all 3 remediation templates
        apply_patch("parameterized_query")
        apply_patch("output_encoding")
        apply_patch("add_security_header")

        with run_demo_app(VULNERABLE_ENV):
            results = verify_all(ALL_VULN_CLASSES)
            for r in results:
                if r.get("security_verified") is True:
                    verified_count += 1

        # Roll back patches after each run
        rollback_patch("parameterized_query")
        rollback_patch("output_encoding")
        rollback_patch("add_security_header")

    return verified_count, total_patches


def evaluate_regression_detection(num_runs):
    """Evaluates detection and rollback of deliberately broken (synthetic regression) patches."""
    total_regressions = num_runs
    caught_count = 0

    broken_sqli_patch = "    results = []\n"
    before_code = REMEDIATION_TEMPLATES["parameterized_query"]["before"]
    app_live = os.path.join(DEMO_APP_DIR, "app.py")

    for _ in range(num_runs):
        restore_pristine_files()

        # Inject synthetic regression: fixes SQLi by parameterizing/stubbing, but breaks search functionality
        with open(app_live, "r") as f:
            content = f.read()

        broken_content = content.replace(before_code, broken_sqli_patch, 1)
        with open(app_live, "w") as f:
            f.write(broken_content)

        with run_demo_app(VULNERABLE_ENV):
            verdicts = run_final_verdict()
            for v in verdicts:
                if v["vulnerability_class"] == "SQL Injection":
                    if v["verdict"] == "REGRESSION" and v.get("rollback_result", {}).get("status") == "ROLLED_BACK":
                        caught_count += 1

        restore_pristine_files()

    return caught_count, total_regressions


def evaluate_end_to_end_time(num_runs):
    """Measures wall-clock time for complete automated pipeline runs."""
    total_time = 0.0

    for _ in range(num_runs):
        restore_pristine_files()

        with run_demo_app(VULNERABLE_ENV):
            t0 = time.time()

            # 1. Scan
            findings = run_scan()

            # 2. Validate
            validated = validate_all(findings)

            # 3. AI Analysis
            analysis = analyze_all(validated)

            # 4. Remediation (Apply patches)
            for item in analysis:
                template = item.get("recommended_template")
                if template:
                    apply_patch(template)

        # 5. Restart app with patched code to verify
        with run_demo_app(VULNERABLE_ENV):
            # 6. Verification + Functionality + Final Verdict
            _verdicts = run_final_verdict()

            t1 = time.time()
            total_time += (t1 - t0)

        # Clean up / rollback patches
        rollback_patch("parameterized_query")
        rollback_patch("output_encoding")
        rollback_patch("add_security_header")
        restore_pristine_files()

    avg_time = total_time / num_runs if num_runs > 0 else 0.0
    return avg_time


def run_evaluation(num_runs=10):
    print(f"\n=======================================================")
    print(f"       SecureAI Benchmark & Pipeline Evaluation       ")
    print(f"=======================================================")
    print(f"Executing {num_runs} runs per benchmark condition...\n")

    app_live = os.path.join(DEMO_APP_DIR, "app.py")
    comments_live = os.path.join(DEMO_APP_DIR, "templates", "comments.html")

    saved_app = None
    saved_comments = None
    if os.path.exists(app_live):
        with open(app_live, "r") as f:
            saved_app = f.read()
    if os.path.exists(comments_live):
        with open(comments_live, "r") as f:
            saved_comments = f.read()

    try:
        # 1. Detection accuracy
        print("[1/5] Evaluating detection accuracy (vulnerabilities enabled)...")
        det_caught, det_total = evaluate_detection_accuracy(num_runs)
        det_pct = (det_caught / det_total * 100.0) if det_total > 0 else 0.0

        # 2. False positive rate
        print("[2/5] Evaluating false positive rate (safe environment flags)...")
        fp_caught, fp_total = evaluate_false_positive_rate(num_runs)
        fp_pct = (fp_caught / fp_total * 100.0) if fp_total > 0 else 0.0

        # 3. Verification accuracy
        print("[3/5] Evaluating verification accuracy (post-patch)...")
        ver_caught, ver_total = evaluate_verification_accuracy(num_runs)
        ver_pct = (ver_caught / ver_total * 100.0) if ver_total > 0 else 0.0

        # 4. Regression detection rate
        print("[4/5] Evaluating regression detection rate (synthetic regressions)...")
        reg_caught, reg_total = evaluate_regression_detection(num_runs)
        reg_pct = (reg_caught / reg_total * 100.0) if reg_total > 0 else 0.0

        # 5. End-to-end execution time
        print("[5/5] Measuring average end-to-end pipeline execution time...")
        avg_time = evaluate_end_to_end_time(num_runs)

        # Results summary
        print("\n" + "=" * 55)
        print(f"=== SecureAI Evaluation Results ({num_runs} runs) ===")
        print("=" * 55)
        print(f"Detection accuracy:        {det_pct:6.1f}% ({det_caught}/{det_total} vulnerable cases correctly flagged)")
        print(f"False positive rate:       {fp_pct:6.1f}% ({fp_caught}/{fp_total} safe cases incorrectly flagged)")
        print(f"Verification accuracy:     {ver_pct:6.1f}% ({ver_caught}/{ver_total} patches correctly verified)")
        print(f"Regression detection rate: {reg_pct:6.1f}% ({reg_caught}/{reg_total} synthetic regressions caught)")
        print(f"Avg end-to-end time:        {avg_time:5.2f}s per full pipeline run")
        print("=" * 55 + "\n")

    finally:
        if saved_app is not None and os.path.exists(app_live):
            with open(app_live, "w") as f:
                f.write(saved_app)
        if saved_comments is not None and os.path.exists(comments_live):
            with open(comments_live, "w") as f:
                f.write(saved_comments)
        kill_port_5002()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run SecureAI evaluation benchmarks.")
    parser.add_argument(
        "--runs",
        type=int,
        default=10,
        help="Number of iterations for each evaluation test (default: 10)",
    )
    args = parser.parse_args()
    run_evaluation(num_runs=args.runs)
