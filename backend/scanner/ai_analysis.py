import json
import os
import re
import requests

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
detected and second-pass validated by the scanning system. Do not
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


def parse_llm_json(raw_text):
    """Safely extract and parse JSON from the LLM text response.
    Handles responses wrapped in markdown code fences or surrounding text.
    """
    text = raw_text.strip()
    # Strip markdown code fences if present (e.g. ```json ... ```)
    if text.startswith("```"):
        match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
        if match:
            text = match.group(1).strip()

    # Find bounding curly braces for JSON object
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        text = text[start : end + 1]

    return json.loads(text)


def real_call_llm(prompt, recommended_template=None, retries=1):
    """Calls Anthropic Claude API using the ANTHROPIC_API_KEY environment variable.
    Returns a dict matching the required analysis schema.
    If the API call or JSON parsing fails, retries once, then falls back gracefully
    to prevent pipeline crashes.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        print("[AI Analysis] ANTHROPIC_API_KEY not set. Falling back to mock response.")
        return mock_call_llm(prompt, recommended_template or "parameterized_query")

    model = os.environ.get("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
    endpoint_url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    payload = {
        "model": model,
        "max_tokens": 1024,
        "temperature": 0.0,
        "messages": [
            {"role": "user", "content": prompt}
        ]
    }

    required_keys = [
        "explanation",
        "impact",
        "severity",
        "severity_justification",
        "recommended_template",
        "risk_of_change",
    ]

    for attempt in range(retries + 1):
        try:
            response = requests.post(endpoint_url, headers=headers, json=payload, timeout=30)
            response.raise_for_status()
            data = response.json()
            raw_text = data["content"][0]["text"]
            parsed = parse_llm_json(raw_text)

            # Ensure all required schema keys exist
            if all(k in parsed for k in required_keys):
                # Ensure recommended_template is preserved if empty
                if not parsed.get("recommended_template") and recommended_template:
                    parsed["recommended_template"] = recommended_template
                return parsed
            else:
                print(f"[AI Analysis] Missing expected keys in LLM JSON (attempt {attempt + 1}).")
        except Exception as e:
            print(f"[AI Analysis] LLM API call/parse error on attempt {attempt + 1}: {e}")

    # Graceful fallback after retry exhaustion
    print("[AI Analysis] Falling back to safe structured default due to LLM error.")
    return {
        "explanation": "Automated security finding analysis (LLM response unavailable or unparseable).",
        "impact": "Potential security impact based on validated vulnerability class.",
        "severity": "HIGH",
        "severity_justification": "Fallback assessment based on validated DAST finding.",
        "recommended_template": recommended_template or "parameterized_query",
        "risk_of_change": "LOW",
    }


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
    if os.environ.get("ANTHROPIC_API_KEY"):
        result = real_call_llm(prompt, recommended_template)
    else:
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