import json
import os
from datetime import datetime

class ScanReporter:
    """Handles structured reporting and exports findings to Markdown, JSON, and professional HTML formats."""
    def __init__(self, target_url):
        self.target_url = target_url
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.findings = []
        self.sections = {}

    def add_finding(self, module=None, severity="INFO", description="", details=None, title=None):
        """Flexible finding adder that supports both module-style and title-style kwargs."""
        mod = module if module else (title if title else "General Audit")
        desc = description if description else (title if title else "No description provided")
        sev = severity.upper() if severity else "INFO"
        
        finding = {
            "module": mod,
            "severity": sev,
            "description": desc,
            "details": details or {}
        }
        self.findings.append(finding)

    def add_section(self, title, data):
        """Adds custom analytical section data to the report."""
        self.sections[title] = data

    def save_markdown(self, filename="scan_report.md"):
        md_content = f"# Security Reconnaissance Report\n\n"
        md_content += f"- **Target:** `{self.target_url}`\n"
        md_content += f"- **Timestamp:** `{self.timestamp}`\n"
        md_content += f"- **Total Findings:** `{len(self.findings)}`\n\n"
        
        md_content += "## Summary of Findings\n"
        if not self.findings and not self.sections:
            md_content += "No critical vulnerabilities or items logged.\n\n"
        else:
            md_content += "| Module / Section | Severity / Type | Description / Details |\n"
            md_content += "| :--- | :--- | :--- |\n"
            for f in self.findings:
                md_content += f"| {f['module']} | **{f['severity']}** | {f['description']} |\n"
            for title, data in self.sections.items():
                md_content += f"| {title} | **INFO** | Analyzed data successfully logged. |\n"

        if self.sections:
            md_content += "\n## Detailed Module Sections\n"
            for title, data in self.sections.items():
                md_content += f"\n### {title}\n"
                md_content += f"```json\n{json.dumps(data, indent=2)}\n```\n"

        with open(filename, "w") as f:
            f.write(md_content)
        print(f"[*] Markdown report successfully saved to {filename}")

    def save_json(self, filename="scan_report.json"):
        report_data = {
            "target": self.target_url,
            "timestamp": self.timestamp,
            "findings": self.findings,
            "sections": self.sections
        }
        with open(filename, "w") as f:
            json.dump(report_data, f, indent=4)
        print(f"[*] JSON report successfully saved to {filename}")

    def save_html(self, filename="scan_report.html"):
        # Compute severity distribution counts
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "WARNING": 0}
        for f in self.findings:
            sev = f["severity"]
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts["INFO"] += 1

        findings_html = ""
        if not self.findings:
            findings_html = "<tr><td colspan='3' style='text-align: center; color: #64748b; padding: 25px;'>No vulnerabilities or items logged.</td></tr>"
        else:
            for f in self.findings:
                sev = f["severity"]
                badge_class = f"badge-{sev.lower()}" if sev.lower() in ["critical", "high", "medium", "low", "warning"] else "badge-info"
                findings_html += f"""
                <tr>
                    <td><strong>{f['module']}</strong></td>
                    <td><span class="badge {badge_class}">{sev}</span></td>
                    <td>{f['description']}</td>
                </tr>
                """

        sections_html = ""
        for title, data in self.sections.items():
            sections_html += f"""
            <div class="section-card">
                <h3>{title}</h3>
                <pre><code>{json.dumps(data, indent=2)}</code></pre>
            </div>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Reconnaissance Report - {self.target_url}</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border-color: #334155;
            --primary: #38bdf8;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --info: #64748b;
            --warning: #f59e0b;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            margin: 0;
            padding: 30px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        header {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 25px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}
        h1 {{
            margin: 0 0 10px 0;
            color: var(--primary);
            font-size: 26px;
        }}
        .metadata {{
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            color: var(--text-muted);
            font-size: 14px;
            margin-top: 15px;
        }}
        .metadata span strong {{
            color: var(--text-main);
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}
        .stat-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }}
        .stat-card .number {{
            font-size: 28px;
            font-weight: bold;
            margin-top: 5px;
        }}
        .stat-card.critical .number {{ color: var(--critical); }}
        .stat-card.high .number {{ color: var(--high); }}
        .stat-card.medium .number {{ color: var(--medium); }}
        .stat-card.low .number {{ color: var(--low); }}
        .stat-card.info .number {{ color: var(--primary); }}
        
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 25px;
        }}
        h2 {{
            font-size: 20px;
            margin-top: 0;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
            color: var(--text-main);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
            font-size: 14px;
        }}
        th {{
            background-color: rgba(51, 65, 85, 0.4);
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 12px;
            letter-spacing: 0.05em;
        }}
        tr:hover {{
            background-color: rgba(51, 65, 85, 0.2);
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .badge-critical {{ background-color: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.4); }}
        .badge-high {{ background-color: rgba(249, 115, 22, 0.2); color: #fdba74; border: 1px solid rgba(249, 115, 22, 0.4); }}
        .badge-medium {{ background-color: rgba(234, 179, 8, 0.2); color: #fde047; border: 1px solid rgba(234, 179, 8, 0.4); }}
        .badge-low {{ background-color: rgba(59, 130, 246, 0.2); color: #93c5fd; border: 1px solid rgba(59, 130, 246, 0.4); }}
        .badge-warning {{ background-color: rgba(245, 158, 11, 0.2); color: #fcd34d; border: 1px solid rgba(245, 158, 11, 0.4); }}
        .badge-info {{ background-color: rgba(100, 116, 139, 0.2); color: #cbd5e1; border: 1px solid rgba(100, 116, 139, 0.4); }}
        
        .section-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        .section-card h3 {{
            margin-top: 0;
            font-size: 16px;
            color: var(--primary);
        }}
        pre {{
            background-color: #090d16;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            border: 1px solid var(--border-color);
            margin: 0;
        }}
        code {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 13px;
            color: #e2e8f0;
        }}
        footer {{
            text-align: center;
            color: var(--text-muted);
            font-size: 13px;
            margin-top: 40px;
            border-top: 1px solid var(--border-color);
            padding-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Security Reconnaissance Report</h1>
            <div class="metadata">
                <span><strong>Target:</strong> {self.target_url}</span>
                <span><strong>Generated:</strong> {self.timestamp}</span>
                <span><strong>Total Findings:</strong> {len(self.findings)}</span>
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card critical">
                <div>Critical</div>
                <div class="number">{severity_counts['CRITICAL']}</div>
            </div>
            <div class="stat-card high">
                <div>High</div>
                <div class="number">{severity_counts['HIGH']}</div>
            </div>
            <div class="stat-card medium">
                <div>Medium</div>
                <div class="number">{severity_counts['MEDIUM']}</div>
            </div>
            <div class="stat-card low">
                <div>Low / Warning</div>
                <div class="number">{severity_counts['LOW'] + severity_counts['WARNING']}</div>
            </div>
            <div class="stat-card info">
                <div>Info / Normal</div>
                <div class="number">{severity_counts['INFO']}</div>
            </div>
        </div>

        <div class="card">
            <h2>Executive Summary & Findings</h2>
            <table>
                <thead>
                    <tr>
                        <th>Module / Section</th>
                        <th>Severity</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_html}
                </tbody>
            </table>
        </div>

        {f'<div class="card"><h2>Detailed Module Data & Payloads</h2>{sections_html}</div>' if self.sections else ''}

        <footer>
            Generated by Modular Async Security Reconnaissance Framework &bull; Confidential Security Audit
        </footer>
    </div>
</body>
</html>
"""

        with open(filename, "w") as f:
            f.write(html_content)
        print(f"[*] HTML executive report successfully saved to {filename}")
