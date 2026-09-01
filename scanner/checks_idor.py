"""
IDOR (Insecure Direct Object Reference) detection.

Approach: find URLs containing a numeric path segment (e.g. /profile/2),
then - while authenticated as a single test user - request nearby IDs
(id-2 .. id+2) and see whether we get a 200 OK with DIFFERENT content
each time instead of a 403/404/redirect-to-login.

If a low-privilege user can pull back distinct, seemingly-personal
data (different usernames/emails/balances) just by changing a number
in the URL, that's a strong IDOR signal. This is a heuristic, not
proof of a specific data leak - a human should confirm the finding.
"""
import re
from urllib.parse import urlparse

NUMERIC_SEGMENT = re.compile(r"(/\D*)(\d+)(/?)$")


def find_idor_candidates(pages):
    """Return URLs that end in a numeric path segment, e.g. /profile/3."""
    candidates = []
    for url in pages:
        path = urlparse(url).path
        if NUMERIC_SEGMENT.search(path):
            candidates.append(url)
    return candidates


def check_idor(session, url, id_range=3):
    findings = []
    match = NUMERIC_SEGMENT.search(url)
    if not match:
        return findings

    prefix, id_str, suffix = match.groups()
    original_id = int(id_str)
    base = url[: match.start()]

    seen_bodies = set()
    accessible_ids = []

    for offset in range(-id_range, id_range + 1):
        test_id = original_id + offset
        if test_id < 0:
            continue
        test_url = f"{base}{prefix}{test_id}{suffix}"
        try:
            resp = session.get(test_url, timeout=10, allow_redirects=False)
        except Exception:
            continue

        if resp.status_code == 200:
            # Normalize whitespace so trivial formatting differences don't
            # count as "different content"
            body_fingerprint = " ".join(resp.text.split())
            if body_fingerprint not in seen_bodies:
                seen_bodies.add(body_fingerprint)
                accessible_ids.append(test_id)

    # If we could access 2+ IDs and got genuinely distinct content each
    # time (not just "not found" pages), that's a signal of missing
    # ownership checks.
    if len(accessible_ids) >= 2:
        findings.append({
            "title": "Possible IDOR - sequential IDs return distinct data",
            "severity": "High",
            "url": base + prefix + id_str + suffix,
            "description": (
                "Requesting nearby numeric IDs on this endpoint returned HTTP 200 "
                "with different content each time, with no visible ownership or "
                "authorization check. This suggests any authenticated user may be "
                "able to view other users' records by changing the ID in the URL."
            ),
            "evidence": f"Accessible IDs without an authorization error: {accessible_ids}",
        })

    return findings
