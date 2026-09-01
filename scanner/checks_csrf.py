"""
CSRF (Cross-Site Request Forgery) detection.

Approach: for every state-changing (POST) form discovered by the
crawler, check whether it includes a hidden anti-CSRF token field.
Real anti-CSRF protection (Flask-WTF's CSRFProtect, Django's
{% csrf_token %}, etc.) always shows up as a hidden input with a
name like 'csrf_token' or '_csrf'. If none is present, the form is
relying purely on the session cookie to authenticate the request -
which a malicious page can trigger from a logged-in victim's browser
without ever needing to read the cookie itself.
"""
from urllib.parse import urljoin

CSRF_FIELD_HINTS = ("csrf", "_token", "authenticity")


def check_csrf(page_url, form):
    findings = []
    if form.get("method") != "post":
        return findings

    field_names = [(i["name"] or "").lower() for i in form["inputs"]]
    if any(any(hint in name for hint in CSRF_FIELD_HINTS) for name in field_names):
        return findings

    action = urljoin(page_url, form["action"]) if form["action"] else page_url
    submitted_fields = ", ".join(n for n in field_names if n) or "(none)"

    findings.append({
        "title": "Cross-Site Request Forgery (CSRF) - missing anti-CSRF token",
        "severity": "High",
        "url": action,
        "description": (
            "This form performs a state-changing action over POST but contains "
            "no hidden anti-CSRF token field. Because browsers automatically "
            "attach session cookies to requests, a malicious page visited by a "
            "logged-in victim could silently auto-submit this exact form and "
            "the server would have no way to distinguish it from a legitimate "
            "request."
        ),
        "evidence": f"POST {action} - submitted fields: {submitted_fields}. No csrf/token field found.",
    })
    return findings
