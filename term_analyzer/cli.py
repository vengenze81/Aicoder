from rich.console import Console
from rich.progress import track, Progress, SpinnerColumn, TextColumn
import asyncio
import argparse
import logging
import sys
import json
import os
from datetime import datetime
from term_analyzer.tester import PortTester
from term_analyzer.db import DatabaseManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s – %(message)s"
)
logger = logging.getLogger("term_analyzer.cli")

def load_config():
    default_config = {
        "ports": "21,22,80,443,3306,8080",
        "wordlist": "custom_paths.txt",
        "ext": "json,html,bak,txt",
        "recursive": True,
        "audit": True,
        "output": "recon_report.html",
        "json_output": "recon_report.json",
        "headers": {},
        "cookies": {},
        "exclude_statuses": [404],
        "exclude_sizes": []
    }
    if os.path.exists("config.json"):
        try:
            with open("config.json", "r") as f:
                user_config = json.load(f)
                default_config.update(user_config)
        except Exception:
            pass
    return default_config

def parse_key_value_pairs(items_list):
    res = {}
    if not items_list:
        return res
    for item in items_list:
        if ":" in item:
            k, v = item.split(":", 1)
            res[k.strip()] = v.strip()
        elif "=" in item:
            k, v = item.split("=", 1)
            res[k.strip()] = v.strip()
    return res

async def run_scan_on_target(target: str, ports_str: str, fuzz: bool = False, audit: bool = False, output: str = None, json_output: str = None, ext: str = None, recursive: bool = False, wordlist: str = None, headers: dict = None, cookies: dict = None, exclude_statuses: list = None, exclude_sizes: list = None) -> None:
    try:
        ports = [int(p.strip()) for p in ports_str.split(",")]
    except ValueError:
        logger.error("Invalid ports format. Please use comma-separated integers (e.g. 80,443,8080).")
        return

    db = DatabaseManager()
    prev_scan = db.get_previous_scan(target)

    logger.info(f"Starting reconnaissance scan on target: {target}")
    tester = PortTester(target, headers=headers, cookies=cookies)
    open_ports = await tester.scan_ports(ports)

    print(f"\n Reconnaissance Results & CVE Audit for {target}")
    console.print("┏━━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┓")
    console.print("┃ Host           ┃ Port ┃ Status ┃ Auth / Access Audit ┃")
    console.print("┡━━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━┩")
    
    scan_results_data = []
    for p in track(ports, description='[cyan]Scanning ports...'):
        status = "closed"
        matched_open = next((item for item in open_ports if item["port"] == p), None)
        if matched_open:
            status = "open"
            
        audit_status = "Secure / N/A"
        if status == "open" and audit:
            audit_res = await tester.audit_service(p, matched_open.get("banner", ""))
            if audit_res["vulnerable"]:
                audit_status = "VULNERABLE / UNKNOWN"
            else:
                audit_status = "Checked / Secure"

        print(f"│ {target:<14} │ {p:<4} │ {status:<6} │ {audit_status:<19} │")
        scan_results_data.append({"port": p, "status": status, "audit": audit_status})

    console.print("└────────────────┴──────┴────────┴─────────────────────┘")

    # Handle HTTP Fuzzing if requested
    fuzz_results = []
    if fuzz:
        web_ports = [p["port"] for p in open_ports if p["port"] in {80, 443, 8080, 8443, 8000, 5000, 9090}]
        if not web_ports:
            web_ports = [p["port"] for p in open_ports]

        paths = ["admin", "login", "api", "dashboard", "config", "status", "test", "v1", "backup", "index"]
        if wordlist:
            try:
                with open(wordlist, "r", encoding="utf-8", errors="ignore") as wf:
                    custom_paths = [line.strip() for line in wf if line.strip() and not line.startswith("#")]
                    if custom_paths:
                        paths = custom_paths
                        logger.info(f"Loaded {len(paths)} paths from custom wordlist: {wordlist}")
            except Exception as e:
                logger.warning(f"Could not read wordlist file {wordlist}: {e}. Falling back to default paths.")

        extensions_list = [e.strip() for e in ext.split(",")] if ext else []

        for port in track(web_ports, description='[cyan]Auditing web endpoints...'):
            scheme = "https" if port in {443, 8443} else "http"
            base_url = f"{scheme}://{target}:{port}"
            logger.info(f"[*] Running web directory fuzzing across {base_url} with {len(paths)} paths...")
            hits = await tester.fuzz_http_endpoints(
                base_url, paths, 
                extensions=extensions_list, 
                recursive=recursive,
                exclude_statuses=exclude_statuses,
                exclude_sizes=exclude_sizes
            )
            if hits:
                for hit in hits:
                    print(f" [+] Found: {hit['url']} [Status: {hit['status']}, Size: {hit['size']} bytes]")
                    fuzz_results.append(hit)
            else:
                logger.info(f"[-] No active endpoints discovered on {base_url} via fuzzer.")

    # Perform Delta Diffing against previous scan
    if prev_scan:
        console.print("\n╭───────────────── Attack Surface Drift (Delta Diff) ─────────────────╮")
        print(f"│ Comparing against previous scan from: {prev_scan['timestamp'][:19]} │")
        
        old_open_ports = {p['port'] for p in prev_scan['ports'] if p['status'] == 'open'}
        curr_open_ports = {p['port'] for p in scan_results_data if p['status'] == 'open'}
        
        new_ports = curr_open_ports - old_open_ports
        closed_ports = old_open_ports - curr_open_ports
        
        if new_ports:
            print(f"│ 🟢 NEW OPEN PORTS: {list(new_ports)}                                     │")
        if closed_ports:
            print(f"│ 🔴 RECENTLY CLOSED PORTS: {list(closed_ports)}                            │")
            
        old_urls = {h['url'] for h in prev_scan['fuzz_hits']}
        curr_urls = {h['url'] for h in fuzz_results}
        new_urls = curr_urls - old_urls
        
        if new_urls:
            print(f"│ 🚀 NEW ENDPOINTS DISCOVERED:                                        │")
            for u in new_urls:
                print(f"│   - {u:<63} │")
        
        if not new_ports and not closed_ports and not new_urls:
            console.print("│ ✨ No changes detected since last scan. Attack surface is stable.     │")
        console.print("╰─────────────────────────────────────────────────────────────────────╯")

    db.save_scan(target, scan_results_data, fuzz_results)
    logger.info(f"[*] Scan results for {target} archived to historical database (analyzer_history.db).")

    # Generate HTML Report if requested
    if output:
        report_filename = output if len(target) == len(output.replace(".html", "")) else f"{output.replace('.html', '')}_{target.replace('.', '_')}.html"
        html_content = f"""<!DOCTYPE html>
<html>
<head>
<title>Term-Analyzer Report - {target}</title>
<style>
  body {{ font-family: Arial, sans-serif; background: #1e1e1e; color: #d4d4d4; padding: 20px; }}
  h1, h2 {{ color: #4ec9b0; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 15px; background: #252526; }}
  th, td {{ border: 1px solid #333333; padding: 10px; text-align: left; }}
  th {{ background: #333333; color: #ffffff; }}
  .vuln {{ color: #f44747; font-weight: bold; }}
  .secure {{ color: #6a9955; font-weight: bold; }}
</style>
</head>
<body>
<h1>Term-Analyzer Reconnaissance Report</h1>
<p><strong>Target:</strong> {target}</p>
<h2>Port & Service Audit</h2>
<table>
<tr><th>Port</th><th>Status</th><th>Audit Result</th></tr>
"""
        for d in scan_results_data:
            cls = "vuln" if "VULNERABLE" in d["audit"] else "secure"
            html_content += f"<tr><td>{d['port']}</td><td>{d['status']}</td><td class='{cls}'>{d['audit']}</td></tr>"
        html_content += "</table>"

        if fuzz_results:
            html_content += "<h2>Discovered Endpoints (Fuzzer)</h2><ul>"
            for hit in fuzz_results:
                html_content += f"<li><a href='{hit['url']}' target='_blank'>{hit['url']}</a> (Status: {hit['status']}, Size: {hit['size']} bytes)</li>"
            html_content += "</ul>"

        html_content += "</body></html>"

        with open(report_filename, "w") as f:
            f.write(html_content)
        print(f"[+] HTML report successfully saved to {report_filename}")

    # Generate JSON Report if requested
    if json_output:
        json_filename = json_output if len(target) == len(json_output.replace(".json", "")) else f"{json_output.replace('.json', '')}_{target.replace('.', '_')}.json"
        json_payload = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "ports": scan_results_data,
            "fuzz_hits": fuzz_results
        }
        with open(json_filename, "w") as jf:
            json.dump(json_payload, jf, indent=4)
        print(f"[+] Structured JSON report successfully saved to {json_filename}")

async def main_async(args):
    config = load_config()

    ports_val = args.ports or config.get("ports", "21,22,80,443,3306,8080")
    wordlist_val = args.wordlist or config.get("wordlist")
    ext_val = args.ext or config.get("ext")
    recursive_val = args.recursive if args.recursive else config.get("recursive", False)
    audit_val = args.audit if args.audit else config.get("audit", False)
    output_val = args.output or config.get("output", "report.html")
    
    json_output_val = None
    if args.json is not None:
        json_output_val = args.json
    elif config.get("json_output"):
        json_output_val = config.get("json_output")

    headers_val = config.get("headers", {})
    if args.header:
        headers_val.update(parse_key_value_pairs(args.header))

    cookies_val = config.get("cookies", {})
    if args.cookie:
        cookies_val.update(parse_key_value_pairs(args.cookie))

    exclude_statuses = config.get("exclude_statuses", [404])
    if args.exclude_status:
        try:
            exclude_statuses = [int(s.strip()) for s in args.exclude_status.split(",") if s.strip()]
        except ValueError:
            pass

    exclude_sizes = config.get("exclude_sizes", [])
    if args.exclude_size:
        try:
            exclude_sizes = [int(sz.strip()) for sz in args.exclude_size.split(",") if sz.strip()]
        except ValueError:
            pass

    targets = []
    if args.scan:
        targets.append(args.scan)
    elif args.cidr:
        logger.info(f"[*] Sweeping CIDR block {args.cidr} for live hosts...")
        dummy_tester = PortTester("127.0.0.1")
        live_hosts = await dummy_tester.discover_live_hosts(args.cidr)
        if not live_hosts:
            logger.warning(f"[-] No live hosts discovered on CIDR range {args.cidr}.")
            return
        logger.info(f"[+] Discovered {len(live_hosts)} live host(s): {live_hosts}")
        targets = live_hosts
    else:
        console.print("Error: Either --scan <ip> or --cidr <subnet> must be specified.")
        sys.exit(1)

    for target in track(targets, description='[cyan]Sweeping targets...'):
        await run_scan_on_target(
            target=target,
            ports_str=ports_val,
            fuzz=args.fuzz,
            audit=audit_val,
            output=output_val,
            json_output=json_output_val,
            ext=ext_val,
            recursive=recursive_val,
            wordlist=wordlist_val,
            headers=headers_val,
            cookies=cookies_val,
            exclude_statuses=exclude_statuses,
            exclude_sizes=exclude_sizes
        )

console = Console()

def main():
    parser = argparse.ArgumentParser(description="Term-Analyzer TUI/CLI Security Toolkit")
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--scan", help="Target IP or hostname to scan")
    group.add_argument("--cidr", help="Target CIDR subnet to sweep (e.g. 192.168.68.0/24)")
    
    parser.add_argument("--ports", help="Comma-separated list of ports")
    parser.add_argument("--fuzz", action="store_true", help="Automatically fuzz discovered web endpoints")
    parser.add_argument("--wordlist", help="Path to custom external text wordlist file for fuzzing")
    parser.add_argument("--ext", help="Comma-separated file extensions to fuzz")
    parser.add_argument("--recursive", action="store_true", help="Recursively crawl discovered subdirectories")
    parser.add_argument("--audit", action="store_true", help="Audit discovered services for unauth access")
    parser.add_argument("--spray", help="Candidate password for HTTP basic auth credential spray")
    parser.add_argument("--passwords-file", help="Path to a password wordlist file for credential spraying")
    parser.add_argument("--output", help="Save scan and finding results to an HTML report")
    parser.add_argument("--json", nargs="?", const="recon_report.json", help="Export scan data to a structured JSON file")
    parser.add_argument("--header", action="append", help="Custom HTTP header (e.g. --header 'Authorization: Bearer xyz')")
    parser.add_argument("--cookie", action="append", help="Custom HTTP cookie (e.g. --cookie 'session_id=12345')")
    parser.add_argument("--exclude-status", help="Comma-separated HTTP status codes to exclude (e.g. 404,403)")
    parser.add_argument("--exclude-size", help="Comma-separated response content lengths in bytes to exclude")
    parser.add_argument("log_file", nargs="?", help="Optional log file path")

    args = parser.parse_args()

    if not args.scan and not args.cidr:
        from term_analyzer.tui import interactive_tui
        asyncio.run(interactive_tui())
    else:
        asyncio.run(main_async(args))

    return 0
if __name__ == "__main__":
    main()

