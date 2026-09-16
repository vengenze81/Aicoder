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
    <title>TermAnalyzer Security Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; max-width: 1000px; margin: auto; }}
        h1, h2 {{ color: #38bdf8; border-bottom: 2px solid #1e293b; padding-bottom: 0.5rem; }}
        .meta {{ background: #1e293b; padding: 1rem; border-radius: 8px; margin-bottom: 2rem; border-left: 4px solid #38bdf8; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 2rem; background: #1e293b; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #0f172a; color: #38bdf8; }}
        .high {{ color: #f87171; font-weight: bold; }}
        .medium {{ color: #fbbf24; font-weight: bold; }}
        .info {{ color: #38bdf8; }}
    </style>
</head>
<body>
    <h1>🛡️ TermAnalyzer Reconnaissance & Security Report</h1>
    <div class="meta">
        <p><strong>Target Scope:</strong> {data["target"]}</p>
        <p><strong>Timestamp:</strong> {data["timestamp"]}</p>
    </div>

    <h2>Discovered Services</h2>
    <table>
        <tr><th>Host</th><th>Port</th><th>Status</th><th>Banner Preview</th></tr>
        {"".join([f"<tr><td>{s["host"]}</td><td>{s["port"]}</td><td>{s["status"]}</td><td>{s["banner"]}</td></tr>" for s in data["services"]]) if data["services"] else "<tr><td colspan=4>No open services found.</td></tr>"}
    </table>

    <h2>Fuzzed Endpoints</h2>
    <table>
        <tr><th>Status</th><th>Size</th><th>Endpoint URL</th></tr>
        {"".join([f"<tr><td>{e["status"]}</td><td>{e["size"]} bytes</td><td>{e["url"]}</td></tr>" for e in data["endpoints"]]) if data["endpoints"] else "<tr><td colspan=3>No endpoints fuzzed or found.</td></tr>"}
    </table>

    <h2>Security Findings & Recommended Actions</h2>
    <table>
        <tr><th>Severity</th><th>Rule ID</th><th>Recommended Action</th></tr>
        {"".join([f"<tr><td class=\"{m["severity"]}\">{m["severity"].upper()}</td><td>{m["rule_id"]}</td><td>{m["action"]}</td></tr>" for m in data["matches"]]) if data["matches"] else "<tr><td colspan=3>No vulnerabilities or rule violations detected.</td></tr>"}
    </table>
</body>
</html>
"""
        path.write_text(html_content)
        console.print(f"[green][+] HTML report successfully saved to {path}[/green]")
    else:
        logger.error(f"Unsupported output file extension: {ext}. Use .json or .html")

async def perform_scan_async(target: str, ports_str: str, fuzz: bool = False, output: str = None) -> None:
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

    services_data = [
        {"host": svc.host, "port": svc.port, "status": svc.status, "banner": svc.banner[:60] if svc.banner else "-"}
        for svc in open_services
    ]

    table = Table(title=f"Reconnaissance Results for {target}")
    table.add_column("Host", style="cyan")
    table.add_column("Port", style="magenta")
    table.add_column("Status", style="green")
    table.add_column("Banner Preview", style="yellow")

    for svc in open_services:
        table.add_row(str(svc.host), str(svc.port), svc.status, svc.banner[:60] if svc.banner else "-")

    console.print(table)

    endpoints_data = []
    web_ports = {80, 443, 8080, 8443, 8000, 5000, 9090}
    web_services = [s for s in open_services if s.port in web_ports or "http" in s.banner.lower()]

    if fuzz and web_services:
        wordlist_path = Path("wordlist.txt")
        if wordlist_path.exists():
            with open(wordlist_path) as f:
                paths = [line.strip() for line in f if line.strip()]
        else:
            paths = ["admin/", "login/", "api/", "swagger.json", ".env", "metrics", "config.json"]

        console.print(f"[bold cyan][*] Running Async HTTP Endpoint Fuzzer on discovered web services...[/bold cyan]")
        for svc in web_services:
            scheme = "https" if svc.port in {443, 8443} else "http"
            base_url = f"{scheme}://{svc.host}:{svc.port}"
            console.print(f"[*] Fuzzing {base_url} across {len(paths)} paths...")
            found_endpoints = await tester.fuzz_http_endpoints(base_url, paths)
            if found_endpoints:
                fuzz_table = Table(title=f"Discovered Endpoints on {base_url}")
                fuzz_table.add_column("Status", style="green")
                fuzz_table.add_column("Size", style="magenta")
                fuzz_table.add_column("Endpoint URL", style="cyan")
                for ep in found_endpoints:
                    fuzz_table.add_row(str(ep["status"]), str(ep["size"]), ep["url"])
                    endpoints_data.append(ep)
                console.print(fuzz_table)
            else:
                console.print(f"[yellow][-] No matching endpoints found on {base_url}[/yellow]")

    engine = RuleEngine()
    log_lines = []
    for svc in open_services:
        if svc.banner:
            log_lines.append(f"info: Discovered open port {svc.port} with banner: {svc.banner}")
        else:
            log_lines.append(f"info: Discovered open port {svc.port}")

    matches = engine.evaluate(log_lines)
    matches_data = [
        {
            "rule_id": m.get("rule_id", "UNKNOWN"),
            "service": m.get("service", "Unknown"),
            "severity": m.get("severity", "info"),
            "action": m.get("action", "Review configuration."),
            "matched_line": m.get("matched_line", "")
        }
        for m in matches
    ]

    if not matches:
        console.print("[green]╭─────────────────── Scan Results ───────────────────╮[/green]")
        console.print("[green]│ ✅ No security issues or rule violations detected. │[/green]")
        console.print("[green]╰────────────────────────────────────────────────────╯[/green]")
    else:
        report_table = Table(title="🛡️ Security & Analysis Report")
        report_table.add_column("Severity", style="bold red")
        report_table.add_column("Rule", style="cyan")
        report_table.add_column("Recommended Action", style="yellow")

        for match in matches:
            sev = match.get("severity", "info").upper()
            rule_id = match.get("rule_id", "UNKNOWN")
            action = match.get("action", "Review configuration.")
            report_table.add_row(sev, rule_id, action)

        console.print(report_table)

    if output:
        report_payload = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "services": services_data,
            "endpoints": endpoints_data,
            "matches": matches_data
        }
        export_report(report_payload, output)

def main():
    parser = argparse.ArgumentParser(description="TermAnalyzer: High-Speed Mobile Offensive Reconnaissance & Rule Engine")
    parser.add_argument("log_file", nargs="?", help="Path to static log file to parse (optional if using --scan)")
    parser.add_argument("--scan", help="Target IP, CIDR block, or local to auto-discover local subnet")
    parser.add_argument("--ports", default="22,80,443,8080,3306,6379", help="Comma-separated ports to scan")
    parser.add_argument("--fuzz", action="store_true", help="Automatically fuzz discovered web endpoints using wordlist.txt")
    parser.add_argument("--output", help="Export scan results to file (.json or .html)")

    args = parser.parse_args()

    if args.scan:
        asyncio.run(perform_scan_async(args.scan, args.ports, fuzz=args.fuzz, output=args.output))
    elif args.log_file:
        logger.info(f"Parsing terminal output stream from {args.log_file}...")
        path = Path(args.log_file)
        if not path.exists():
            logger.error(f"Log file not found: {args.log_file}")
            sys.exit(1)
        content = path.read_text(errors="ignore")
        engine = RuleEngine()
        matches = engine.evaluate(content.splitlines())
        
        matches_data = [{
            "rule_id": m.get("rule_id", "UNKNOWN"),
            "service": m.get("service", "Unknown"),
            "severity": m.get("severity", "info"),
            "action": m.get("action", "Review configuration."),
            "matched_line": m.get("matched_line", "")
        } for m in matches]

        if not matches:
            console.print("[green]╭─────────────────── Scan Results ───────────────────╮[/green]")
            console.print("[green]│ ✅ No security issues or rule violations detected. │[/green]")
            console.print("[green]╰────────────────────────────────────────────────────╯[/green]")
        else:
            report_table = Table(title="🛡️ Security & Analysis Report")
            report_table.add_column("Severity", style="bold red")
            report_table.add_column("Rule", style="cyan")
            report_title = "Recommended Action"
            report_table.add_column(report_title, style="yellow")

            for match in matches:
                report_table.add_row(match.get("severity", "info").upper(), match.get("rule_id", "UNKNOWN"), match.get("action", "Review configuration."))
            console.print(report_table)

        if args.output:
            report_payload = {
                "target": args.log_file,
                "timestamp": datetime.now().isoformat(),
                "services": [],
                "endpoints": [],
                "matches": matches_data
            }
            export_report(report_payload, args.output)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
