"""
Reflected XSS detection.

Approach: inject a unique, easily-identifiable marker wrapped in a
<script> tag into each input, then check whether the marker comes
back UNESCAPED in the response HTML. If Flask/Jinja2 (or any
templating engine) is escaping properly, we'd see &lt;script&gt;
instead of a literal <script> tag.
"""
from urllib.parse import urljoin
import re

MARKER = "xsschk9182"
PAYLOAD = f"<script>alert('{MARKER}')</script>"


def check_xss_form(session, page_url, form):
    findings = []
    action = urljoin(page_url, form["action"]) if form["action"] else page_url
    method = form["method"]
    text_inputs = [i for i in form["inputs"] if i["name"] and i["type"] in ("text", "search", "email")]

    for target_input in text_inputs:
        data = {i["name"]: "test" for i in text_inputs}
        data[target_input["name"]] = PAYLOAD
        try:
            if method == "post":
                resp = session.post(action, data=data, timeout=5)
            else:
                resp = session.get(action, params=data, timeout=5)
        except Exception:
            continue

        if PAYLOAD in resp.text:
            findings.append({
                "title": f"Reflected XSS in '{target_input['name']}'",
                "severity": "High",
                "url": action,
                "description": (
                    f"The '{target_input['name']}' field reflects user input into the "
                    "page without HTML-escaping. An attacker could craft a link that "
                    "executes arbitrary JavaScript in a victim's browser."
                ),
                "evidence": f"Payload {PAYLOAD!r} was reflected unescaped in the response.",
            })

    return findings


def check_xss_url_params(session, url):
    """Also test GET-based endpoints directly via query string (e.g. ?q=)."""
    findings = []
    if "?" not in url:
        return findings
    base, _, qs = url.partition("?")
    params = {}
    for pair in qs.split("&"):
        if "=" in pair:
            k, _ = pair.split("=", 1)
            params[k] = PAYLOAD

    if not params:
        return findings

    try:
        resp = session.get(base, params=params, timeout=5)
    except Exception:
        return findings

    if PAYLOAD in resp.text:
        findings.append({
            "title": f"Reflected XSS in URL parameter(s) {list(params.keys())}",
            "severity": "High",
            "url": base,
            "description": (
                "Query string parameters are reflected into the page without "
                "escaping, allowing script injection via a crafted URL."
            ),
            "evidence": f"Payload {PAYLOAD!r} was reflected unescaped in the response.",
        })
    return findings
