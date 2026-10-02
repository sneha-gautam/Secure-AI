import json
import sys
import os
from urllib.parse import urljoin, urlparse, parse_qsl, urlunparse

import requests
from bs4 import BeautifulSoup

# Allow importing the controlled demo app.
sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "demo_app",
    ),
)

REQUEST_TIMEOUT = 8
MAX_PAGES = 20

KNOWN_INPUTS = {
    "/login": ["username", "password"],
    "/search": ["query"],
    "/comments": ["comment"],
}


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


def same_origin(base_url, candidate_url):
    base = urlparse(base_url)
    candidate = urlparse(candidate_url)

    return (
        candidate.scheme in ("http", "https")
        and candidate.netloc == base.netloc
    )


def _is_demo_target(base_url):
    parsed = urlparse(normalize_url(base_url))

    return (
        parsed.hostname in ("127.0.0.1", "localhost")
        and parsed.port == 5002
    )


def _build_demo_model(app, base_url):
    """
    Build the Security Model for the controlled Flask demo app.

    Flask route introspection gives us the actual routes/methods,
    while KNOWN_INPUTS documents the intentionally controlled
    demo inputs.
    """

    routes = []

    for rule in app.url_map.iter_rules():

        if rule.endpoint == "static":
            continue

        path = str(rule)

        methods = sorted(
            method
            for method in rule.methods
            if method not in ("HEAD", "OPTIONS")
        )

        route_entry = {
            "path": path,
            "methods": methods,
        }

        if path in KNOWN_INPUTS:
            route_entry["inputs"] = KNOWN_INPUTS[path]

        routes.append(route_entry)

    routes.sort(key=lambda route: route["path"])

    return {
        "application": "SecureAI Demo Application",
        "base_url": normalize_url(base_url),
        "routes": routes,
        "pages": [
            {
                "url": urljoin(normalize_url(base_url), route["path"]),
                "path": route["path"],
            }
            for route in routes
        ],
        "parameters": [
            {
                "url": urljoin(
                    normalize_url(base_url),
                    "/search",
                ),
                "parameter": "query",
                "method": "GET",
            }
        ],
        "forms": [
            {
                "page": urljoin(
                    normalize_url(base_url),
                    "/comments",
                ),
                "action": urljoin(
                    normalize_url(base_url),
                    "/comments",
                ),
                "method": "POST",
                "inputs": [
                    {
                        "name": "comment",
                        "type": "text",
                    }
                ],
            }
        ],
    }


def _discover_external_target(base_url):
    """
    Lightweight HTTP discovery for an authorized external target.

    Discovers:
    - reachable HTML pages
    - GET parameters
    - HTML forms
    - form input names
    """

    base_url = normalize_url(base_url)

    session = requests.Session()

    queue = [base_url]
    visited = set()

    pages = []
    parameters = []
    forms = []

    while queue and len(visited) < MAX_PAGES:

        current = queue.pop(0)

        parsed_current = urlparse(current)

        clean_current = urlunparse((
            parsed_current.scheme,
            parsed_current.netloc,
            parsed_current.path or "/",
            "",
            parsed_current.query,
            "",
        ))

        if clean_current in visited:
            continue

        visited.add(clean_current)

        try:
            response = session.get(
                clean_current,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
        except requests.RequestException:
            continue

        pages.append({
            "url": response.url,
            "path": urlparse(response.url).path or "/",
            "status_code": response.status_code,
            "content_type": response.headers.get(
                "Content-Type",
                "",
            ),
        })

        parsed_response = urlparse(response.url)

        for name, value in parse_qsl(
            parsed_response.query,
            keep_blank_values=True,
        ):
            parameters.append({
                "url": response.url,
                "parameter": name,
                "value": value,
                "method": "GET",
            })

        content_type = response.headers.get(
            "Content-Type",
            "",
        )

        if "text/html" not in content_type:
            continue

        soup = BeautifulSoup(
            response.text,
            "html.parser",
        )

        # -----------------------------------------------------
        # Links
        # -----------------------------------------------------

        for link in soup.find_all("a", href=True):

            candidate = urljoin(
                response.url,
                link["href"],
            )

            if not same_origin(base_url, candidate):
                continue

            parsed_candidate = urlparse(candidate)

            clean_candidate = urlunparse((
                parsed_candidate.scheme,
                parsed_candidate.netloc,
                parsed_candidate.path or "/",
                "",
                parsed_candidate.query,
                "",
            ))

            if (
                clean_candidate not in visited
                and clean_candidate not in queue
                and len(visited) + len(queue) < MAX_PAGES
            ):
                queue.append(clean_candidate)

        # -----------------------------------------------------
        # Forms
        # -----------------------------------------------------

        for form in soup.find_all("form"):

            action = urljoin(
                response.url,
                form.get("action", ""),
            )

            method = form.get(
                "method",
                "get",
            ).upper()

            if not same_origin(base_url, action):
                continue

            inputs = []

            for field in form.find_all(
                ["input", "textarea", "select"]
            ):
                name = field.get("name")

                if not name:
                    continue

                inputs.append({
                    "name": name,
                    "type": field.get(
                        "type",
                        "text",
                    ),
                })

            forms.append({
                "page": response.url,
                "action": action,
                "method": method,
                "inputs": inputs,
            })

    return {
        "application": "External Authorized Target",
        "base_url": base_url,
        "routes": [],
        "pages": pages,
        "parameters": parameters,
        "forms": forms,
    }


def build_security_model(app_or_url, base_url=None):
    """
    Unified Security Model entry point.

    Demo:
        build_security_model(flask_app, base_url)

    External target:
        build_security_model(target_url)
    """

    if isinstance(app_or_url, str):

        target_url = normalize_url(app_or_url)

        if _is_demo_target(target_url):

            # Import the controlled demo Flask app only when needed.
            from app import app as demo_app

            return _build_demo_model(
                demo_app,
                target_url,
            )

        return _discover_external_target(
            target_url,
        )

    # Backward-compatible Flask-app mode.
    if base_url is None:
        raise ValueError(
            "base_url is required when building a model from a Flask app."
        )

    return _build_demo_model(
        app_or_url,
        base_url,
    )


def save_model(
    model,
    path="security_model.json",
):
    with open(path, "w") as file:
        json.dump(
            model,
            file,
            indent=2,
        )

    return path


if __name__ == "__main__":

    target = (
        "http://127.0.0.1:5002"
    )

    model = build_security_model(
        target
    )

    print(
        json.dumps(
            model,
            indent=2,
        )
    )

    saved_path = save_model(
        model
    )

    print(
        f"\nSaved to: {saved_path}"
    )