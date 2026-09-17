import json
import os
from datetime import datetime

class ScanReporter:
    def __init__(self, target_url):
        self.target_url = target_url
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.findings = []

    def add_result(self, url, status_code, route_type, size, regex_matches=None, header_gaps=None):
        record = {
            "url": url,
            "status_code": status_code,
            "route_type": route_type,
            "size": size,
            "regex_matches": regex_matches or [],
            "header_gaps": header_gaps or []
        }
        self.findings.append(record)

    def save_json(self, filename=None):
        if not filename:
            filename = f"recon_report_{self.timestamp}.json"
        
        report_data = {
            "target": self.target_url,
            "scan_time": self.timestamp,
            "total_findings": len(self.findings),
            "results": self.findings
        }
        
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)
        print(f"\n[+] Scan report successfully exported to JSON: {filename}")

    def save_markdown(self, filename=None):
        if not filename:
            filename = f"recon_report_{self.timestamp}.md"
            
        md_content = f"# Security Reconnaissance Report\n\n"
        md_content += f"- **Target Domain:** {self.target_url}\n"
        md_content += f"- **Scan Timestamp:** {self.timestamp}\n"
        md_content += f"- **Total Active Endpoints Discovered:** {len(self.findings)}\n\n"
        md_content += "---\n\n## Endpoint Details\n\n"
        
        for item in self.findings:
            md_content += f"### `{item['url']}`\n"
            md_content += f"- **Status Code:** HTTP {item['status_code']}\n"
            md_content += f"- **Route Type:** {item['route_type']}\n"
            md_content += f"- **Content Size:** {item['size']} bytes\n"
            
            if item['regex_matches']:
                md_content += f"- **Regex Matches:**\n"
                for match in item['regex_matches']:
                    md_content += f"  - `{match}`\n"
                    
            if item['header_gaps']:
                md_content += f"- **Security Header Gaps:**\n"
                for gap in item['header_gaps']:
                    md_content += f"  - ⚠️ {gap}\n"
            md_content += "\n---\n"
            
        with open(filename, "w", encoding="utf-8") as f:
            f.write(md_content)
        print(f"[+] Scan report successfully exported to Markdown: {filename}")
