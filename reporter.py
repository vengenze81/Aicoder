import json
import os
from datetime import datetime

class ScanReporter:
    """Handles structured reporting and exports findings to Markdown and JSON formats."""
    def __init__(self, target_url):
        self.target_url = target_url
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.findings = []
        self.sections = {}

    def add_finding(self, module=None, severity="INFO", description="", details=None, title=None):
        """Flexible finding adder that supports both module-style and title-style kwargs."""
        mod = module if module else (title if title else "General Audit")
        desc = description if description else (title if title else "No description provided")
        
        finding = {
            "module": mod,
            "severity": severity,
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
