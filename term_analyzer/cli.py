import asyncio
import argparse
import logging
import sys
from term_analyzer.tester import PortTester, discover_local_interfaces
from term_analyzer.db import DatabaseManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s – %(message)s"
)
logger = logging.getLogger("term_analyzer.cli")

async def perform_scan_async(target: str, ports_str: str, fuzz: bool = False, audit: bool = False, spray_pass: str = None, output: str = None, ext: str = None, recursive: bool = False, wordlist: str = None) -> None:
    try:
        ports = [int(p.strip()) for p in ports_str.split(",")]
    except ValueError:
        logger.error("Invalid ports format. Please use comma-separated integers (e.g. 80,443,8080).")
        return

    db = DatabaseManager()
    prev_scan = db.get_previous_scan(target)

    logger.info(f"Starting concurrent async reconnaissance scan on {target} across ports: {ports}")
    tester = PortTester(target)
    open_ports = await tester.scan_ports(ports)

    # Print Reconnaissance Table
    print(f" Reconnaissance Results & CVE Audit for {target}")
    print("┏━━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┓")
    print("┃ Host           ┃ Port ┃ Status ┃ Auth / Access Audit ┃")
    print("┡━━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━┩")
    
    scan_results_data = []
    for p in ports:
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

    print("└────────────────┴──────┴────────┴─────────────────────┘")

    # Handle HTTP Fuzzing if requested
    fuzz_results = []
    if fuzz:
        web_ports = [p["port"] for p in open_ports if p["port"] in {80, 443, 8080, 8443, 8000, 5000, 9090}]
        if not web_ports:
            web_ports = [p["port"] for p in open_ports]

        # Determine paths from wordlist or defaults
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

        for port in web_ports:
            scheme = "https" if port in {443, 8443} else "http"
            base_url = f"{scheme}://{target}:{port}"
            logger.info(f"[*] Running web directory fuzzing across {base_url} with {len(paths)} paths (Extensions: {extensions_list}, Recursive: {recursive})...")
            hits = await tester.fuzz_http_endpoints(base_url, paths, extensions=extensions_list, recursive=recursive)
            if hits:
                for hit in hits:
                    print(f" [+] Found: {hit['url']} [Status: {hit['status']}, Size: {hit['size']} bytes]")
                    fuzz_results.append(hit)
            else:
                logger.info(f"[-] No active endpoints discovered on {base_url} via fuzzer.")

    # Handle Credential Spray if requested
    spray_results = []
    if spray_pass:
        web_ports = [p["port"] for p in open_ports if p["port"] in {80, 443, 8080, 8443, 8000, 5000, 9090}] or [p["port"] for p in open_ports]
        try:
            with open("users.txt", "r") as f:
                usernames = [line.strip() for line in f if line.strip()]
        except Exception:
            usernames = ["admin", "root", "user", "guest", "test"]

        for port in web_ports:
            scheme = "https" if port in {443, 8443} else "http"
            base_url = f"{scheme}://{target}:{port}"
            logger.info(f"[*] Running Async HTTP Credential Spray across {len(usernames)} users with password: {spray_pass}...")
            sprayed = await tester.credential_spray_http(base_url, usernames, spray_pass)
            if sprayed:
                for res in sprayed:
                    print(f" [!] SUCCESS: Username '{res['username']}' with password '{res['password']}' on {base_url}")
                    spray_results.append(res)
            else:
                logger.info(f"[-] No valid credentials found on {base_url} with password {spray_pass}")

    # Perform Delta Diffing against previous scan
    if prev_scan:
        print("\n╭───────────────── Attack Surface Drift (Delta Diff) ─────────────────╮")
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
            print("│ ✨ No changes detected since last scan. Attack surface is stable.     │")
        print("╰─────────────────────────────────────────────────────────────────────╯")

    # Save current scan to history database
    db.save_scan(target, scan_results_data, fuzz_results)
    logger.info("[*] Scan results successfully archived to historical database (analyzer_history.db).")

    print("╭─────────────────── Scan Results ───────────────────╮")
    if audit and any(d["audit"].startswith("VULNERABLE") for d in scan_results_data):
        print("│ ⚠️ Vulnerabilities or insecure access detected!   │")
    elif fuzz_results or spray_results:
        print("│ ⚠️ Active endpoints or credentials discovered.      │")
    else:
        print("│ ✅ No security issues or CVE matches detected.     │")
    print("╰────────────────────────────────────────────────────╯")

    # Generate HTML Report if requested
    if output:
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

        if spray_results:
            html_content += "<h2>Credential Spray Successes</h2><ul>"
            for res in spray_results:
                html_content += f"<li>User: <strong>{res['username']}</strong> / Pass: <strong>{res['password']}</strong></li>"
            html_content += "</ul>"

        html_content += "</body></html>"

        with open(output, "w") as f:
            f.write(html_content)
        print(f"[+] HTML report successfully saved to {output}")

def main():
    parser = argparse.ArgumentParser(description="Term-Analyzer TUI/CLI Security Toolkit")
    parser.add_argument("--scan", help="Target IP or hostname to scan")
    parser.add_argument("--ports", default="21,22,80,443,3306,8080", help="Comma-separated list of ports")
    parser.add_argument("--fuzz", action="store_true", help="Automatically fuzz discovered web endpoints")
    parser.add_argument("--wordlist", help="Path to custom external text wordlist file for fuzzing")
    parser.add_argument("--ext", help="Comma-separated file extensions to fuzz (e.g. json,php,bak,txt)")
    parser.add_argument("--recursive", action="store_true", help="Recursively crawl discovered subdirectories")
    parser.add_argument("--audit", action="store_true", help="Audit discovered services for unauth access")
    parser.add_argument("--spray", help="Candidate password for HTTP basic auth credential spray")
    parser.add_argument("--output", help="Save scan and finding results to an HTML report")
    parser.add_argument("log_file", nargs="?", help="Optional log file path")

    args = parser.parse_args()

    if not args.scan:
        parser.print_help()
        sys.exit(1)

    asyncio.run(perform_scan_async(
        target=args.scan,
        ports_str=args.ports,
        fuzz=args.fuzz,
        audit=args.audit,
        spray_pass=args.spray,
        output=args.output,
        ext=args.ext,
        recursive=args.recursive,
        wordlist=args.wordlist
    ))

if __name__ == "__main__":
    main()
