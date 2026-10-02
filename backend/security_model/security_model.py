import json
import sys
import os

# Allow importing the demo app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "demo_app"))

# Explicit input-field mapping — see design note above for why this isn't
# derived from HTML parsing in the current scope.
KNOWN_INPUTS = {
    "/login": ["username", "password"],
    "/search": ["query"],
    "/comments": ["comment"],
}


def build_security_model(app, base_url):
    """
    Introspects a Flask app's url_map to build a lightweight structural model.
    Routes and methods are discovered dynamically; input fields are looked up
    from the explicit KNOWN_INPUTS mapping above.
    """
    routes = []

    for rule in app.url_map.iter_rules():
        # Skip Flask's built-in static file route — not relevant to the model
        if rule.endpoint == "static":
            continue

        path = str(rule)
        methods = sorted(m for m in rule.methods if m not in ("HEAD", "OPTIONS"))

        route_entry = {
            "path": path,
            "methods": methods,
        }

        if path in KNOWN_INPUTS:
            route_entry["inputs"] = KNOWN_INPUTS[path]

        routes.append(route_entry)

    # Sort for stable, readable output
    routes.sort(key=lambda r: r["path"])

    return {
        "application": "SecureAI Demo Application",
        "base_url": base_url,
        "routes": routes,
    }


def save_model(model, path="security_model.json"):
    with open(path, "w") as f:
        json.dump(model, f, indent=2)
    return path


if __name__ == "__main__":
    # Import the demo app's Flask instance directly (not by running it)
    from app import app as demo_app

    model = build_security_model(demo_app, base_url="http://127.0.0.1:5002")
    print(json.dumps(model, indent=2))

    saved_path = save_model(model)
    print(f"\nSaved to: {saved_path}")
