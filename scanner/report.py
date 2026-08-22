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
        rows = ""
        for f in self.sorted_findings():
            color = SEVERITY_COLOR.get(f.severity, "#888")
            rows += f"""
            <div class="finding">
                <div class="finding-header" style="border-left: 5px solid {color};">
                    <span class="severity" style="background:{color};">{escape(f.severity)}</span>
                    <span class="title">{escape(f.title)}</span>
                </div>
                <div class="finding-body">
                    <p><strong>URL:</strong> <code>{escape(f.url)}</code></p>
                    <p>{escape(f.description)}</p>
                    {f'<pre class="evidence">{escape(f.evidence)}</pre>' if f.evidence else ''}
                </div>
            </div>
            """

        summary_counts = {}
        for f in self.findings:
            summary_counts[f.severity] = summary_counts.get(f.severity, 0) + 1
        summary_html = "".join(
            f'<span class="badge" style="background:{SEVERITY_COLOR.get(sev, "#888")};">{sev}: {count}</span>'
            for sev, count in sorted(summary_counts.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 99))
        )

        return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Scan Report - {escape(self.target)}</title>
<style>
    body {{ font-family: -apple-system, Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; color: #222; }}
    h1 {{ font-size: 1.4em; }}
    .meta {{ color: #666; margin-bottom: 20px; }}
    .badge {{ color: white; padding: 4px 10px; border-radius: 4px; font-size: 0.85em; margin-right: 8px; }}
    .finding {{ margin-bottom: 18px; border: 1px solid #ddd; border-radius: 6px; overflow: hidden; }}
    .finding-header {{ padding: 10px 14px; background: #fafafa; }}
    .severity {{ color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; margin-right: 10px; }}
    .title {{ font-weight: bold; }}
    .finding-body {{ padding: 10px 14px; }}
    code {{ background: #f2f2f2; padding: 2px 5px; border-radius: 3px; }}
    .evidence {{ background: #f8f8f8; border: 1px solid #eee; padding: 10px; overflow-x: auto; font-size: 0.85em; }}
</style>
</head>
<body>
    <h1>Web Vulnerability Scan Report</h1>
    <div class="meta">
        Target: <code>{escape(self.target)}</code><br>
        Scanned: {self.started_at.strftime('%Y-%m-%d %H:%M:%S')}<br>
        Total findings: {len(self.findings)}
    </div>
    <div>{summary_html}</div>
    <h2>Findings</h2>
    {rows if self.findings else '<p>No vulnerabilities detected.</p>'}
</body>
</html>"""

    def save_html(self, path):
        with open(path, "w") as f:
            f.write(self.to_html())
