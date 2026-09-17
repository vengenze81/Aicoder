import asyncio
import argparse
import sys

from vuln_scanner import scan_wordpress_plugins
from file_scanner import scan_sensitive_files
from xmlrpc_tester import test_xmlrpc
from header_scanner import scan_security_headers
from waf_profiler import profile_waf
from auth_tester import run_credential_audit
from js_extractor import extract_javascript_assets
from subdomain_enum import enumerate_subdomains
from port_scanner import scan_ports
from reporter import ScanReporter

async def main():
    parser = argparse.ArgumentParser(description="Modular Async Security Reconnaissance Framework")
    parser.add_argument("target", help="Target URL (e.g., https://medistore.se)")
    parser.add_argument("--vuln-scan", action="store_true", help="Run WordPress plugin vulnerability scan")
    parser.add_argument("--file-scan", action="store_true", help="Run sensitive file & backup scanner")
    parser.add_argument("--xmlrpc-test", action="store_true", help="Test XML-RPC amplification vectors")
    parser.add_argument("--header-scan", action="store_true", help="Audit security headers")
    parser.add_argument("--waf-profile", action="store_true", help="Profile WAF rate-limiting")
    parser.add_argument("--auth-audit", action="store_true", help="Run credential audit")
    parser.add_argument("--js-extract", action="store_true", help="Extract JS secrets and endpoints")
    parser.add_argument("--subdomain-enum", action="store_true", help="Enumerate active subdomains")
    parser.add_argument("--port-scan", action="store_true", help="Run async port and service banner scan")
    parser.add_argument("--all", action="store_true", help="Run all security modules sequentially")

    args = parser.parse_args()
    target_url = args.target
    reporter = ScanReporter(target_url)

    print(f"[*] Initializing security scan framework against: {target_url}")

    if args.all or args.port_scan:
        print("\n[*] Executing Async Port & Banner Scan...")
        await scan_ports(target_url, reporter=reporter)

    if args.all or args.subdomain_enum:
        print("\n[*] Executing Subdomain Enumeration...")
        await enumerate_subdomains(target_url, reporter=reporter)

    if args.all or args.vuln_scan:
        print("\n[*] Executing Plugin Vulnerability Scan...")
        await scan_wordpress_plugins(target_url, reporter=reporter)

    if args.all or args.file_scan:
        print("\n[*] Executing Sensitive File & Backup Exposure Scan...")
        await scan_sensitive_files(target_url, reporter=reporter)

    if args.all or args.xmlrpc_test:
        print("\n[*] Executing XML-RPC Probe...")
        await test_xmlrpc(target_url, reporter=reporter)

    if args.all or args.header_scan:
        print("\n[*] Executing Security Header Audit...")
        await scan_security_headers(target_url, reporter=reporter)

    if args.all or args.waf_profile:
        print("\n[*] Executing WAF Concurrency & Rate-Limit Profiler...")
        await profile_waf(target_url, reporter=reporter)

    if args.all or args.auth_audit:
        print("\n[*] Executing Credential Audit...")
        await run_credential_audit(target_url, "discovered_usernames.txt", "passwords.txt")

    if args.all or args.js_extract:
        print("\n[*] Executing JavaScript Secret & Endpoint Extractor...")
        await extract_javascript_assets(target_url, reporter=reporter)

    # Save all report formats
    reporter.save_markdown()
    reporter.save_json()
    reporter.save_html()
    print(f"\n[+] Audit completed. Reports saved to scan_report.md, scan_report.json, and scan_report.html")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 main.py <TARGET_URL> [MODULE_FLAGS]")
        sys.argv.append("--help")
    asyncio.run(main())
