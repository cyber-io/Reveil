"""
Security header and cookie-flag checks. These aren't exploitable bugs
by themselves, but their absence is a well-known indicator of weak
security posture - the kind of thing every real scanner (ZAP, Nikto,
securityheaders.com) checks first.
"""

RECOMMENDED_HEADERS = {
    "Content-Security-Policy": "Mitigates XSS and data injection by restricting allowed content sources.",
    "X-Frame-Options": "Prevents clickjacking by controlling whether the page can be framed.",
    "X-Content-Type-Options": "Prevents MIME-sniffing attacks (should be 'nosniff').",
    "Strict-Transport-Security": "Forces browsers to use HTTPS for future requests.",
    "Referrer-Policy": "Controls how much referrer information is leaked to other sites.",
}


def check_headers(resp, url):
    findings = []
    for header, reason in RECOMMENDED_HEADERS.items():
        if header not in resp.headers:
            findings.append({
                "title": f"Missing security header: {header}",
                "severity": "Low",
                "url": url,
                "description": reason,
                "evidence": "",
            })
    return findings


def check_cookie_flags(resp, url):
    findings = []
    for cookie in resp.cookies:
        issues = []
        if not cookie.secure:
            issues.append("missing Secure flag")
        has_httponly = cookie.has_nonstandard_attr("HttpOnly") or getattr(cookie, "_rest", {}).get("HttpOnly")
        if not has_httponly:
            issues.append("missing HttpOnly flag")
        if issues:
            findings.append({
                "title": f"Cookie '{cookie.name}' set with weak flags",
                "severity": "Medium",
                "url": url,
                "description": (
                    f"Cookie '{cookie.name}' is {', '.join(issues)}. Without HttpOnly, "
                    "JavaScript (including injected XSS payloads) can read the cookie. "
                    "Without Secure, it may be sent over unencrypted HTTP."
                ),
                "evidence": "",
            })
    return findings
