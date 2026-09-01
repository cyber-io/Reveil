"""
Broken Access Control detection (vertical privilege escalation /
missing function-level authorization).

This is different from checks_idor.py, which is about *horizontal*
access - one user reading another user's record by changing an ID.
This check is about *vertical* access: whether a low-privileged,
authenticated session can reach administrative/privileged
functionality at all, regardless of any ID in the URL.

Approach: flag any crawled page whose path looks administrative or
privileged (admin, manage, settings, panel, config, internal) and
confirm it's reachable - HTTP 200, no redirect to a login/error page
- using the same session the scanner authenticated with. If the
scanner logged in as an ordinary user and can still load the page,
the server isn't checking role/permission before serving it.
"""
from urllib.parse import urlparse

SENSITIVE_PATH_KEYWORDS = ("admin", "manage", "internal", "config", "panel")


def find_bac_candidates(pages):
    candidates = []
    for url in pages:
        path = urlparse(url).path.lower()
        if any(kw in path for kw in SENSITIVE_PATH_KEYWORDS):
            candidates.append(url)
    return candidates


def check_bac(session, url):
    findings = []
    try:
        resp = session.get(url, timeout=10, allow_redirects=False)
    except Exception:
        return findings

    if resp.status_code == 200:
        findings.append({
            "title": "Broken Access Control - privileged page reachable without role check",
            "severity": "Critical",
            "url": url,
            "description": (
                "This endpoint looks administrative or privileged based on its "
                "URL, and was reachable with HTTP 200 using a regular "
                "authenticated session - with no redirect to a login or error "
                "page. This suggests the server checks only whether a user is "
                "logged in, not whether they hold the role or permission "
                "required for this function."
            ),
            "evidence": f"GET {url} as an authenticated non-admin user returned HTTP {resp.status_code}.",
        })
    return findings
