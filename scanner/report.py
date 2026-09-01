"""
Report generation for the scanner - collects findings and renders
them as console output and a standalone HTML report.
"""
from datetime import datetime
from html import escape


class Finding:
    def __init__(self, title, severity, url, description, evidence=""):
        self.title = title
        self.severity = severity  # Critical / High / Medium / Low / Info
        self.url = url
        self.description = description
        self.evidence = evidence

    def __repr__(self):
        return f"<Finding {self.severity}: {self.title} @ {self.url}>"

    def to_dict(self):
        return {
            "title": self.title,
            "severity": self.severity,
            "url": self.url,
            "description": self.description,
            "evidence": self.evidence,
        }


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEVERITY_COLOR = {
    "Critical": "#7a0000",
    "High": "#c0392b",
    "Medium": "#e67e22",
    "Low": "#f1c40f",
    "Info": "#3498db",
}


class Report:
    def __init__(self, target):
        self.target = target
        self.findings = []
        self.started_at = datetime.now()

    def add(self, title, severity, url, description, evidence=""):
        self.findings.append(Finding(title, severity, url, description, evidence))

    def sorted_findings(self):
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    def severity_counts(self):
        counts = {sev: 0 for sev in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def to_dict(self):
        return {
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "total_findings": len(self.findings),
            "severity_counts": self.severity_counts(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }

    def print_console(self):
        print("\n" + "=" * 70)
        print(f"  SCAN REPORT: {self.target}")
        print(f"  {len(self.findings)} finding(s) - {self.started_at.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)
        if not self.findings:
            print("\n  No vulnerabilities detected.\n")
            return
        for f in self.sorted_findings():
            print(f"\n[{f.severity}] {f.title}")
            print(f"  URL: {f.url}")
            print(f"  {f.description}")
            if f.evidence:
                print(f"  Evidence: {f.evidence}")
        print("\n" + "=" * 70)

    def to_html(self):
        findings_html = ""
        for f in self.sorted_findings():
            color = SEVERITY_COLOR.get(f.severity, "#888")
            sev_class = f.severity.lower()
            
            # Contextual remediation snippet based on finding type
            remediation = ""
            cwe_tag = ""
            title_lower = f.title.lower()
            if "sql injection" in title_lower or "sqli" in title_lower:
                cwe_tag = "CWE-89: SQL Injection | OWASP A03:2021-Injection"
                remediation = "Use parameterized queries (prepared statements) or an ORM for all database access. Never concatenate user input directly into SQL strings."
            elif "xss" in title_lower:
                cwe_tag = "CWE-79: Cross-Site Scripting (XSS) | OWASP A03:2021-Injection"
                remediation = "Ensure all untrusted input is contextually HTML-escaped before rendering. Avoid Jinja2 '|safe' filters unless content is pre-sanitized with Bleach."
            elif "idor" in title_lower:
                cwe_tag = "CWE-639: Insecure Direct Object References | OWASP A01:2021-Broken Access Control"
                remediation = "Enforce server-side authorization checks on every object request. Verify that the authenticated session user owns or is authorized to view the requested ID."
            elif "missing security header" in title_lower:
                cwe_tag = "CWE-693: Protection Mechanism Failure | OWASP A05:2021-Security Misconfiguration"
                remediation = f"Configure the web server or application middleware to return the '{escape(f.title.split(':')[-1].strip())}' header in all HTTP responses."
            elif "cookie" in title_lower:
                cwe_tag = "CWE-614 / CWE-1004: Sensitive Cookie Without Security Flags | OWASP A05:2021"
                remediation = "Configure session cookies with 'HttpOnly', 'Secure', and 'SameSite=Lax' (or Strict) attributes to prevent script access and unencrypted transmission."

            findings_html += f"""
            <div class="finding-card sev-{sev_class}">
                <div class="finding-header">
                    <span class="severity-badge sev-{sev_class}">{escape(f.severity)}</span>
                    <h3 class="finding-title">{escape(f.title)}</h3>
                </div>
                <div class="finding-body">
                    <div class="detail-row">
                        <span class="detail-label">TARGET ENDPOINT:</span>
                        <code class="endpoint-code">{escape(f.url)}</code>
                    </div>
                    {f'<div class="cwe-pill">{escape(cwe_tag)}</div>' if cwe_tag else ''}
                    <div class="desc-box">
                        <div class="section-title">ANALYSIS & IMPACT</div>
                        <p>{escape(f.description)}</p>
                    </div>
                    {f'''<div class="evidence-box">
                        <div class="section-title">TECHNICAL EVIDENCE & TEST VECTOR</div>
                        <pre class="evidence-content">{escape(f.evidence)}</pre>
                    </div>''' if f.evidence else ''}
                    {f'''<div class="remediation-box">
                        <div class="section-title">RECOMMENDED REMEDIATION</div>
                        <p>{escape(remediation)}</p>
                    </div>''' if remediation else ''}
                </div>
            </div>
            """

        summary_counts = self.severity_counts()
        badges_html = "".join(
            f'''<div class="metric-card sev-{sev.lower()}">
                <div class="metric-val">{summary_counts.get(sev, 0)}</div>
                <div class="metric-label">{sev.upper()}</div>
            </div>'''
            for sev in ["Critical", "High", "Medium", "Low", "Info"]
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Assessment Report - {escape(self.target)}</title>
<style>
    :root {{
        --bg: #0A0D14;
        --surface: #101522;
        --surface-card: #151C2C;
        --border: #202A3E;
        --border-bright: #2E3C57;
        --text: #E6EDF3;
        --text-muted: #8B949E;
        --text-dim: #546076;
        --accent: #00F0FF;
        --critical: #FF334B;
        --high: #FF7B00;
        --medium: #FFB800;
        --low: #38BDF8;
        --info: #94A3B8;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
        background: var(--bg);
        color: var(--text);
        line-height: 1.6;
        padding: 40px 20px;
    }}
    .container {{
        max-width: 960px;
        margin: 0 auto;
    }}
    .header {{
        border-bottom: 1px solid var(--border);
        padding-bottom: 24px;
        margin-bottom: 30px;
    }}
    .brand-tag {{
        display: inline-flex;
        align-items: center;
        gap: 8px;
        font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
        font-size: 12px;
        color: var(--accent);
        letter-spacing: 1.5px;
        text-transform: uppercase;
        margin-bottom: 8px;
    }}
    .brand-tag::before {{
        content: "";
        width: 8px; height: 8px;
        background: var(--accent);
        border-radius: 50%;
        box-shadow: 0 0 8px var(--accent);
    }}
    h1 {{
        font-size: 26px;
        font-weight: 700;
        letter-spacing: -0.5px;
        color: #FFFFFF;
        margin-bottom: 12px;
    }}
    .meta-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 16px;
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 16px 20px;
        margin-top: 16px;
        font-family: 'SFMono-Regular', Consolas, monospace;
        font-size: 13px;
    }}
    .meta-item {{ display: flex; flex-direction: column; gap: 4px; }}
    .meta-label {{ color: var(--text-dim); font-size: 11px; letter-spacing: 1px; }}
    .meta-value {{ color: var(--text); word-break: break-all; }}
    
    .metrics-summary {{
        display: grid;
        grid-template-columns: repeat(5, 1fr);
        gap: 12px;
        margin-bottom: 32px;
    }}
    .metric-card {{
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 6px;
        padding: 14px 10px;
        text-align: center;
    }}
    .metric-card.sev-critical {{ border-top: 3px solid var(--critical); }}
    .metric-card.sev-high {{ border-top: 3px solid var(--high); }}
    .metric-card.sev-medium {{ border-top: 3px solid var(--medium); }}
    .metric-card.sev-low {{ border-top: 3px solid var(--low); }}
    .metric-card.sev-info {{ border-top: 3px solid var(--info); }}
    .metric-val {{ font-size: 24px; font-weight: 700; font-family: monospace; }}
    .metric-card.sev-critical .metric-val {{ color: var(--critical); }}
    .metric-card.sev-high .metric-val {{ color: var(--high); }}
    .metric-card.sev-medium .metric-val {{ color: var(--medium); }}
    .metric-card.sev-low .metric-val {{ color: var(--low); }}
    .metric-card.sev-info .metric-val {{ color: var(--info); }}
    .metric-label {{ font-size: 11px; color: var(--text-dim); letter-spacing: 1px; margin-top: 4px; }}

    .section-heading {{
        font-size: 18px;
        font-weight: 600;
        margin-bottom: 20px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        border-bottom: 1px solid var(--border);
        padding-bottom: 8px;
    }}

    .findings-container {{ display: flex; flex-direction: column; gap: 20px; }}
    .finding-card {{
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 8px;
        overflow: hidden;
    }}
    .finding-card.sev-critical {{ border-left: 4px solid var(--critical); }}
    .finding-card.sev-high {{ border-left: 4px solid var(--high); }}
    .finding-card.sev-medium {{ border-left: 4px solid var(--medium); }}
    .finding-card.sev-low {{ border-left: 4px solid var(--low); }}
    .finding-card.sev-info {{ border-left: 4px solid var(--info); }}

    .finding-header {{
        padding: 16px 20px;
        background: var(--surface-card);
        border-bottom: 1px solid var(--border);
        display: flex;
        align-items: center;
        gap: 12px;
    }}
    .severity-badge {{
        font-family: monospace;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.5px;
        padding: 3px 10px;
        border-radius: 4px;
        text-transform: uppercase;
        color: #0B0E14;
    }}
    .severity-badge.sev-critical {{ background: var(--critical); color: #fff; }}
    .severity-badge.sev-high {{ background: var(--high); color: #000; }}
    .severity-badge.sev-medium {{ background: var(--medium); color: #000; }}
    .severity-badge.sev-low {{ background: var(--low); color: #000; }}
    .severity-badge.sev-info {{ background: var(--info); color: #fff; }}

    .finding-title {{
        font-size: 16px;
        font-weight: 600;
        color: #FFFFFF;
    }}
    .finding-body {{ padding: 20px; display: flex; flex-direction: column; gap: 14px; }}
    .detail-row {{ display: flex; align-items: center; gap: 10px; font-size: 13px; font-family: monospace; }}
    .detail-label {{ color: var(--text-dim); font-size: 11px; }}
    .endpoint-code {{
        background: #080B10;
        border: 1px solid var(--border);
        color: var(--accent);
        padding: 3px 8px;
        border-radius: 4px;
        word-break: break-all;
    }}
    .cwe-pill {{
        font-family: monospace;
        font-size: 11px;
        color: var(--text-dim);
        background: #0A0F18;
        border: 1px solid var(--border);
        padding: 3px 8px;
        border-radius: 4px;
        width: fit-content;
    }}
    .section-title {{
        font-size: 11px;
        letter-spacing: 1px;
        font-weight: 700;
        color: var(--text-dim);
        margin-bottom: 6px;
        text-transform: uppercase;
    }}
    .desc-box, .remediation-box {{ font-size: 14px; color: var(--text-muted); line-height: 1.6; }}
    .evidence-box {{
        background: #07090E;
        border: 1px solid var(--border);
        border-radius: 6px;
        padding: 12px 14px;
    }}
    .evidence-content {{
        font-family: 'SFMono-Regular', Consolas, monospace;
        font-size: 12px;
        color: #D1D5DB;
        white-space: pre-wrap;
        word-break: break-word;
    }}
    .remediation-box {{
        background: rgba(0, 240, 255, 0.03);
        border: 1px solid rgba(0, 240, 255, 0.15);
        border-radius: 6px;
        padding: 12px 14px;
    }}
    .no-findings-box {{
        text-align: center;
        padding: 40px;
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 8px;
        color: var(--text-muted);
    }}
    @media (max-width: 700px) {{
        .metrics-summary {{ grid-template-columns: repeat(2, 1fr); }}
    }}
    @media print {{
        body {{ background: #fff; color: #000; padding: 0; }}
        .finding-card, .meta-grid, .metric-card {{ border-color: #ddd; background: #fff; color: #000; }}
        .evidence-box {{ background: #f5f5f5; border-color: #ccc; color: #000; }}
        .evidence-content {{ color: #000; }}
        .remediation-box {{ background: #f0fdf4; border-color: #86efac; color: #000; }}
    }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div class="brand-tag">REVEIL SECURITY SUITE</div>
        <h1>Web Vulnerability Assessment Report</h1>
        <div class="meta-grid">
            <div class="meta-item">
                <span class="meta-label">TARGET URL</span>
                <span class="meta-value">{escape(self.target)}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">ASSESSMENT DATE</span>
                <span class="meta-value">{self.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">TOTAL FINDINGS</span>
                <span class="meta-value">{len(self.findings)} Vulnerabilities</span>
            </div>
        </div>
    </div>

    <div class="metrics-summary">
        {badges_html}
    </div>

    <div class="section-heading">
        <span>VULNERABILITY FINDINGS BREAKDOWN</span>
        <span style="font-size: 13px; color: var(--text-dim); font-family: monospace;">TOTAL: {len(self.findings)}</span>
    </div>

    <div class="findings-container">
        {findings_html if self.findings else '<div class="no-findings-box">✓ No vulnerabilities detected on the scanned endpoints.</div>'}
    </div>
</div>
</body>
</html>"""

    def save_html(self, path):
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_html())

