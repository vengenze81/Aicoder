import asyncio
import argparse
import sys
import json
import logging
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table

from term_analyzer.rules import RuleEngine
from tester import PortTester, discover_local_interfaces

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s – %(message)s")
logger = logging.getLogger("term_analyzer.cli")

console = Console()

def export_report(data: dict, output_path: str):
    path = Path(output_path)
    ext = path.suffix.lower()
    
    if ext == ".json":
        path.write_text(json.dumps(data, indent=4))
        console.print(f"[green][+] JSON report successfully saved to {path}[/green]")
    elif ext == ".html":
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>TermAnalyzer Security & Spray Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; max-width: 1000px; margin: auto; }}
        h1, h2 {{ color: #38bdf8; border-bottom: 2px solid #1e293b; padding-bottom: 0.5rem; }}
        .meta {{ background: #1e293b; padding: 1rem; border-radius: 8px; margin-bottom: 2rem; border-left: 4px solid #38bdf8; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 2rem; background: #1e293b; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #0f172a; color: #38bdf8; }}
        .high {{ color: #f87171; font-weight: bold; }}
        .success {{ color: #4ade80; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>🛡️ TermAnalyzer Reconnaissance & Credential Spray Report</h1>
    <div class="meta">
        <p><strong>Target Scope:</strong> {data["target"]}</p>
        <p><strong>Timestamp:</strong> {data["timestamp"]}</p>
    </div>

    <h2>Discovered Services & Audits</h2>
    <table>
        <tr><th>Host</th><th>Port</th><th>Status</th><th>Audit Finding</th></tr>
        {"".join([f"<tr><td>{s["host"]}</td><td>{s["port"]}</td><td>{s["status"]}</td><td class=\"high\">{s["audit"]}</td></tr>" if s["audit"] else f"<tr><td>{s["host"]}</td><td>{s["port"]}</td><td>{s["status"]}</td><td>Secure / Closed</td></tr>" for s in data["services"]]) if data["services"] else "<tr><td colspan='4'>No open services found.</td></tr>"}
    </table>

    <h2>Credential Spray Results</h2>
    <table>
        <tr><th>Target URL</th><th>Username</th><th>Password</th><th>Status</th></tr>
        {"".join([f"<tr><td>{r["url"]}</td><td class=\"success\">{r["username"]}</td><td>{r["password"]}</td><td>{r["status"]} (SUCCESS)</td></tr>" for r in data["spray_results"]]) if data["spray_results"] else "<tr><td colspan='4'>No successful credential sprays recorded.</td></tr>"}
    </table>

    <h2>CVE Vulnerability & Exploit Advisory</h2>
    <table>
        <tr><th>Severity</th><th>CVSS</th><th>CVE / Rule ID</th><th>Remediation Action</th></tr>
        {"".join([f"<tr><td class=\"{m["severity"]}\">{m["severity"].upper()}</td><td>{m["cvss"]}</td><td>{m["rule_id"]}</td><td>{m["action"]}</td></tr>" for m in data["matches"]]) if data["matches"] else "<tr><td colspan='4'>No known vulnerabilities matched.</td></tr>"}
    </table>
</body>
</html>
"""
        path.write_text(html_content)
        console.print(f"[green][+] HTML report successfully saved to {path}[/green]")
    else:
        logger.error(f"Unsupported output file extension: {ext}. Use .json or .html")

async def perform_scan_async(target: str, ports_str: str, fuzz: bool = False, audit: bool = False, spray_pass: str = None, output: str = None) -> None:
    if not PortTester:
        raise RuntimeError("PortTester module (`tester.py`) could not be imported.")

    if target.lower() == "local":
        interfaces = discover_local_interfaces()
        non_loopback = [ip for ip in interfaces if not ip.startswith("127.")]
        if non_loopback:
            base_ip = non_loopback[0]
            parts = base_ip.split(".")
            if len(parts) == 4:
                target = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            else:
                target = base_ip
        else:
            target = "127.0.0.1"
        logger.info(f"Auto-resolved local scan target to: {target}")

    try:
        ports = [int(p.strip()) for p in ports_str.split(",")]
    except ValueError:
        logger.error("Invalid port format. Provide comma-separated integers (e.g. 22,80,443).")
        sys.exit(1)

    logger.info(f"Starting concurrent async reconnaissance scan on {target} across ports: {ports}")
    tester = PortTester(target=target)

    if "/" in target:
        open_services = await tester.scan_subnet(target, ports)
    else:
        open_services = await tester.scan_ports(ports)

    services_data = []
    audit_findings = []

    table = Table(title=f"Reconnaissance Results & CVE Audit for {target}")
    table.add_column("Host", style="cyan")
    table.add_column("Port", style="magenta")
    table.add_column("Status", style="green")
    table.add_column("Auth / Access Audit", style="bold red")

    for svc in open_services:
        audit_res = {"vulnerable": False, "details": ""}
        if audit:
            audit_res = await PortTester(target=svc.host).audit_service(svc.port, svc.banner)
        
        finding = audit_res["details"] if audit_res["vulnerable"] else "Secure / N/A"
        services_data.append({
            "host": svc.host, 
            "port": svc.port, 
            "status": svc.status, 
            "banner": svc.banner[:60] if svc.banner else "-",
            "audit": finding
        })
        if audit_res["vulnerable"]:
            audit_findings.append(f"HIGH: [{svc.host}:{svc.port}] {finding}")

        table.add_row(str(svc.host), str(svc.port), svc.status, finding)

    console.print(table)

    endpoints_data = []
    spray_results_data = []
    web_ports = {80, 443, 8080, 8443, 8000, 5000, 9090}
    web_services = [s for s in open_services if s.port in web_ports or "http" in s.banner.lower()]

    if fuzz and web_services:
        wordlist_path = Path("wordlist.txt")
        paths = [line.strip() for line in open(wordlist_path)] if wordlist_path.exists() else ["admin/", "login/", "api/"]
        for svc in web_services:
            scheme = "https" if svc.port in {443, 8443} else "http"
            base_url = f"{scheme}://{svc.host}:{svc.port}"
            found = await tester.fuzz_http_endpoints(base_url, paths)
            for ep in found:
                endpoints_data.append(ep)

    if spray_pass and web_services:
        userlist_path = Path("users.txt")
        if userlist_path.exists():
            usernames = [line.strip() for line in open(userlist_path) if line.strip()]
        else:
            usernames = ["admin", "root", "user", "guest", "administrator", "postgres", "tomcat"]

        console.print(f"[bold cyan][*] Running Async HTTP Credential Spray across {len(usernames)} users with password: {spray_pass}...[/bold cyan]")
        for svc in web_services:
            scheme = "https" if svc.port in {443, 8443} else "http"
            base_url = f"{scheme}://{svc.host}:{svc.port}"
            hits = await tester.credential_spray_http(base_url, usernames, spray_pass)
            if hits:
                spray_table = Table(title=f"Credential Spray Successes on {base_url}")
                spray_table.add_column("Username", style="green")
                spray_table.add_column("Password", style="yellow")
                spray_table.add_column("Status Code", style="cyan")
                for hit in hits:
                    spray_table.add_row(hit["username"], hit["password"], str(hit["status"]))
                    spray_results_data.append({
                        "url": base_url,
                        "username": hit["username"],
                        "password": hit["password"],
                        "status": hit["status"]
                    })
                    audit_findings.append(f"HIGH: Credential spray success ({hit['username']}:{hit['password']}) at {base_url}")
                console.print(spray_table)
            else:
                console.print(f"[yellow][-] No valid credentials found on {base_url} with password {spray_pass}[/yellow]")

    engine = RuleEngine()
    log_lines = []
    for svc in open_services:
        if svc.banner:
            log_lines.append(f"info: Discovered open port {svc.port} with banner: {svc.banner}")
        else:
            log_lines.append(f"info: Discovered open port {svc.port}")
    for af in audit_findings:
        log_lines.append(f"critical: {af}")

    matches = engine.evaluate(log_lines)
    matches_data = [
        {
            "rule_id": m.get("rule_id", "UNKNOWN"),
            "service": m.get("service", "Unknown"),
            "severity": m.get("severity", "info"),
            "cvss": m.get("cvss", "N/A"),
            "description": m.get("description", ""),
            "action": m.get("action", "Review configuration."),
            "matched_line": m.get("matched_line", "")
        }
        for m in matches
    ]

    if not matches and not audit_findings:
        console.print("[green]╭─────────────────── Scan Results ───────────────────╮[/green]")
        console.print("[green]│ ✅ No security issues or CVE matches detected.     │[/green]")
        console.print("[green]╰────────────────────────────────────────────────────╯[/green]")
    else:
        report_table = Table(title="🚨 CVE Exploit Suggester & Vulnerability Advisory")
        report_table.add_column("Severity", style="bold red")
        report_table.add_column("CVSS", style="magenta")
        report_table.add_column("CVE / Rule", style="cyan")
        report_table.add_column("Remediation Action", style="yellow")

        for match in matches:
            report_table.add_row(match.get("severity", "info").upper(), match.get("cvss", "N/A"), match.get("rule_id", "UNKNOWN"), match.get("action", "Review configuration."))

        for af in audit_findings:
            if "spray success" in af.lower():
                report_table.add_row("HIGH", "9.8", "CREDENTIAL-SPRAY-HIT", "Disable default accounts or enforce multi-factor authentication.")
            elif "UNAUTH" in af:
                report_table.add_row("HIGH", "9.8", "UNAUTH-ACCESS", "Restrict access or enforce authentication.")

        console.print(report_table)

    if output:
        report_payload = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "services": services_data,
            "endpoints": endpoints_data,
            "spray_results": spray_results_data,
            "matches": matches_data
        }
        export_report(report_payload, output)

def main():
    parser = argparse.ArgumentParser(description="TermAnalyzer: High-Speed Mobile Offensive Reconnaissance & Rule Engine")
    parser.add_argument("log_file", nargs="?", help="Path to static log file to parse")
    parser.add_argument("--scan", help="Target IP, CIDR block, or local")
    parser.add_argument("--ports", default="22,80,443,8080,3306,6379", help="Comma-separated ports to scan")
    parser.add_argument("--fuzz", action="store_true", help="Automatically fuzz discovered web endpoints")
    parser.add_argument("--audit", action="store_true", help="Audit discovered services for unauth access")
    parser.add_argument("--spray", help="Candidate password to perform credential spraying across discovered web services")
    parser.add_argument("--output", help="Export scan results to file (.json or .html)")

    args = parser.parse_args()

    if args.scan:
        asyncio.run(perform_scan_async(args.scan, args.ports, fuzz=args.fuzz, audit=args.audit, spray_pass=args.spray, output=args.output))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
