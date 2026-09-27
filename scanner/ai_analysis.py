TEMPLATE_MAP = {
    "SQL Injection": "parameterized_query",
    "XSS": "output_encoding",
    "Missing Security Headers": "add_security_header",
}


def build_prompt(validated_finding):
    vuln_class = validated_finding["vulnerability_class"]
    endpoint = validated_finding["endpoint"]
    evidence = validated_finding["original_finding"]
    recommended_template = TEMPLATE_MAP[vuln_class]

    prompt = f"""You are a security analysis assistant. A vulnerability has already been
detected and independently validated by a separate scanning system. Do not
question whether it is real — your job is only to explain it, assess severity,
and justify a remediation choice from a fixed template.

Vulnerability class: {vuln_class}
Endpoint: {endpoint}
Evidence: {evidence}
Fixed remediation template to recommend: {recommended_template}

Respond ONLY with a JSON object, no other text, matching exactly this schema:
{{
  "explanation": "string",
  "impact": "string",
  "severity": "HIGH | MEDIUM | LOW",
  "severity_justification": "string",
  "recommended_template": "{recommended_template}",
  "risk_of_change": "LOW | MEDIUM | HIGH"
}}
"""
    return prompt


def mock_call_llm(prompt, recommended_template):
    # Placeholder — simulates what the real API will return.
    return {
        "explanation": "This is a placeholder explanation generated without a real LLM call.",
        "impact": "Placeholder impact description.",
        "severity": "HIGH",
        "severity_justification": "Placeholder justification.",
        "recommended_template": recommended_template,
        "risk_of_change": "LOW",
    }


def filter_vulnerable(validated_findings):
    return [f for f in validated_findings if f["first_pass_vulnerable"] and f["validated"]]


def analyze_finding(validated_finding):
    vuln_class = validated_finding["vulnerability_class"]
    recommended_template = TEMPLATE_MAP[vuln_class]

    prompt = build_prompt(validated_finding)
    result = mock_call_llm(prompt, recommended_template)
    return result


def analyze_all(validated_findings):
    vulnerable_only = filter_vulnerable(validated_findings)
    return [analyze_finding(f) for f in vulnerable_only]


if __name__ == "__main__":
    from scanner import run_scan
    from validator import validate_all

    scan_results = run_scan()
    validated_results = validate_all(scan_results)
    analysis_results = analyze_all(validated_results)

    for result in analysis_results:
        print(result)