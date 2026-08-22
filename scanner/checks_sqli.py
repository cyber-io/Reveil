"""
SQL Injection detection.

Approach: error-based + auth-bypass detection.
  1. Error-based: submit a payload with an unbalanced quote and look for
     SQL error strings leaking into the response.
  2. Auth-bypass: for login-shaped forms, try classic tautology payloads
     and check whether we land somewhere that looks like a logged-in
     page instead of an error/login page.

This mirrors how real scanners like sqlmap start (though sqlmap goes
much further with blind/time-based/boolean techniques).
"""
from urllib.parse import urljoin

SQL_ERROR_SIGNATURES = [
    "sql syntax", "sqlite3.operationalerror", "sqlite3.error",
    "unclosed quotation mark", "you have an error in your sql syntax",
    "odbc sql server driver", "pg::syntaxerror", "warning: mysql",
    "database error",
]

ERROR_PAYLOAD = "'"
AUTH_BYPASS_PAYLOADS = ["' OR '1'='1", "admin'--", "' OR 1=1--"]


def _looks_like_sql_error(text):
    low = text.lower()
    return any(sig in low for sig in SQL_ERROR_SIGNATURES)


def check_sqli(session, page_url, form):
    """Tests a single form for SQL injection. Returns list of finding dicts."""
    findings = []
    action = urljoin(page_url, form["action"]) if form["action"] else page_url
    method = form["method"]
    text_inputs = [i for i in form["inputs"] if i["name"] and i["type"] in ("text", "password", "email", "search")]

    if not text_inputs:
        return findings

    # --- Error-based check: inject a lone quote into each field ---
    data = {i["name"]: "test" for i in text_inputs}
    for target_input in text_inputs:
        payload_data = dict(data)
        payload_data[target_input["name"]] = ERROR_PAYLOAD
        try:
            if method == "post":
                resp = session.post(action, data=payload_data, timeout=5)
            else:
                resp = session.get(action, params=payload_data, timeout=5)
        except Exception:
            continue
        if _looks_like_sql_error(resp.text):
            findings.append({
                "title": f"SQL Injection (error-based) in '{target_input['name']}'",
                "severity": "Critical",
                "url": action,
                "description": (
                    f"Submitting a single quote in the '{target_input['name']}' field "
                    "triggered a database error visible in the response. This strongly "
                    "suggests unsanitized input is being concatenated into a SQL query."
                ),
                "evidence": f"Payload: {target_input['name']}=' | Error signature found in response",
            })

    # --- Auth-bypass check: only makes sense for login-shaped forms ---
    field_names = {i["name"].lower() for i in text_inputs}
    has_user_field = any(n in field_names for n in ("username", "user", "email", "login"))
    has_pass_field = any(i["type"] == "password" for i in text_inputs)

    if has_user_field and has_pass_field and method == "post":
        for payload in AUTH_BYPASS_PAYLOADS:
            payload_data = {}
            for i in text_inputs:
                if i["type"] == "password":
                    payload_data[i["name"]] = "irrelevant"
                else:
                    payload_data[i["name"]] = payload
            try:
                resp = session.post(action, data=payload_data, timeout=5, allow_redirects=True)
            except Exception:
                continue
            # Heuristic: successful bypass usually redirects away from the
            # login page and no longer shows a login form/error text.
            low = resp.text.lower()
            if resp.url != action and "invalid" not in low and "login" not in resp.url.lower():
                findings.append({
                    "title": "SQL Injection - Authentication Bypass",
                    "severity": "Critical",
                    "url": action,
                    "description": (
                        "A classic SQL injection payload in the username field "
                        "bypassed authentication entirely, without a valid password."
                    ),
                    "evidence": f"Payload: username={payload}",
                })
                break  # one confirmed bypass is enough evidence

    return findings
