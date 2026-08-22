#!/usr/bin/env python3
"""
Web Vulnerability Scanner
=========================
A small educational scanner that crawls a target, then checks for:
  - SQL injection (error-based + auth-bypass)
  - Reflected XSS
  - IDOR (sequential ID access)
  - Missing security headers / weak cookie flags

Usage:
    python3 scanner.py http://127.0.0.1:5000 --login alice:alice123 --login-url /login
    python3 scanner.py http://127.0.0.1:5000
"""
import argparse
import sys
import requests

from crawler import crawl
from report import Report
from checks_sqli import check_sqli
from checks_xss import check_xss_form, check_xss_url_params
from checks_idor import find_idor_candidates, check_idor
from checks_headers import check_headers, check_cookie_flags


def try_login(session, base_url, login_url, credentials):
    username, _, password = credentials.partition(":")
    full_url = base_url.rstrip("/") + login_url
    try:
        resp = session.post(full_url, data={"username": username, "password": password}, timeout=5)
        print(f"[*] Logged in as '{username}' (status {resp.status_code}, final URL {resp.url})")
    except Exception as e:
        print(f"[!] Login attempt failed: {e}")


def run_scan(target, login_url=None, credentials=None, max_pages=25, on_log=None):
    def log(msg):
        print(msg)
        if on_log:
            on_log(msg)

    def add_finding(report, f):
        report.add(**f)
        log(f"[!] {f['severity']}: {f['title']}")

    session = requests.Session()
    report = Report(target)

    if login_url and credentials:
        username, _, password = credentials.partition(":")
        full_url = target.rstrip("/") + login_url
        try:
            resp = session.post(full_url, data={"username": username, "password": password}, timeout=5)
            log(f"[*] Logged in as '{username}' (status {resp.status_code}, final URL {resp.url})")
        except Exception as e:
            log(f"[!] Login attempt failed: {e}")

    log(f"[*] Crawling {target} ...")
    pages, forms = crawl(session, target, max_pages=max_pages)
    log(f"[*] Discovered {len(pages)} page(s) and {len(forms)} form(s)")

    # --- Header checks: site-wide, deduplicated (same missing header on
    #     every page is one finding, not one per page) ---
    log("[*] Checking security headers and cookie flags ...")
    missing_header_urls = {}  # title -> {description, urls: set()}
    seen_cookie_findings = set()

    for url in pages:
        try:
            resp = session.get(url, timeout=5)
        except Exception:
            continue
        for f in check_headers(resp, url):
            entry = missing_header_urls.setdefault(f["title"], {"description": f["description"], "urls": set()})
            entry["urls"].add(url)
        for f in check_cookie_flags(resp, url):
            key = f["title"]
            if key not in seen_cookie_findings:
                seen_cookie_findings.add(key)
                add_finding(report, f)

    for title, info in missing_header_urls.items():
        urls = sorted(info["urls"])
        shown = ", ".join(urls[:3]) + (f" (+{len(urls)-3} more)" if len(urls) > 3 else "")
        f = dict(
            title=title,
            severity="Low",
            url=target,
            description=info["description"],
            evidence=f"Missing on {len(urls)} page(s): {shown}",
        )
        add_finding(report, f)

    # --- SQLi + XSS checks on every discovered form ---
    log(f"[*] Testing {len(forms)} form(s) for SQL injection ...")
    for page_url, form in forms:
        for f in check_sqli(session, page_url, form):
            add_finding(report, f)

    log(f"[*] Testing {len(forms)} form(s) for reflected XSS ...")
    for page_url, form in forms:
        for f in check_xss_form(session, page_url, form):
            add_finding(report, f)

    log("[*] Testing URL query parameters for reflected XSS ...")
    for url in pages:
        for f in check_xss_url_params(session, url):
            add_finding(report, f)

    # --- IDOR checks on numeric-ID URLs ---
    candidates = find_idor_candidates(pages)
    log(f"[*] Testing {len(candidates)} numeric-ID endpoint(s) for IDOR ...")
    for url in candidates:
        for f in check_idor(session, url):
            add_finding(report, f)

    log(f"[*] Scan complete - {len(report.findings)} finding(s)")
    return report


def main():
    parser = argparse.ArgumentParser(description="Educational web vulnerability scanner")
    parser.add_argument("target", help="Target base URL, e.g. http://127.0.0.1:5000")
    parser.add_argument("--login-url", help="Path to the login endpoint, e.g. /login")
    parser.add_argument("--login", help="Credentials as username:password")
    parser.add_argument("--max-pages", type=int, default=25, help="Max pages to crawl")
    parser.add_argument("--out", default="scan_report.html", help="Path to write the HTML report")
    args = parser.parse_args()

    report = run_scan(args.target, login_url=args.login_url, credentials=args.login, max_pages=args.max_pages)
    report.print_console()
    report.save_html(args.out)
    print(f"\n[*] HTML report written to {args.out}")


if __name__ == "__main__":
    sys.exit(main())
