import sys
import asyncio
import argparse
from engine import run_stealth_scanner
from auth_tester import run_credential_audit
from vuln_scanner import scan_wordpress_plugins
from api_fuzzer import fuzz_api_endpoints
from file_scanner import scan_sensitive_files
from xmlrpc_tester import test_xmlrpc
from header_scanner import scan_security_headers
from waf_profiler import profile_waf
from reporter import ScanReporter
from config import PROXY_LIST

def load_wordlist(filepath):
    endpoints = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if not line.startswith('/'):
                        line = '/' + line
                    endpoints.append(line)
    except FileNotFoundError:
        print(f"[-] Wordlist file not found: {filepath}. Falling back to default baseline path.")
        endpoints = ["/"]
    return endpoints

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Modular Asynchronous Stealth Security Reconnaissance & Audit Engine")
    parser.add_argument("target", help="Target base URL (e.g., https://example.com)")
    parser.add_argument("-w", "--wordlist", default="wordlist.txt", help="Path to endpoint wordlist file (default: wordlist.txt)")
    parser.add_argument("-c", "--concurrency", type=int, default=5, help="Maximum concurrent requests (default: 5)")
    parser.add_argument("-t", "--timeout", type=float, default=8.0, help="Request timeout in seconds (default: 8.0)")
    parser.add_argument("-H", "--header", action="append", help="Custom header in 'Key: Value' format")
    parser.add_argument("-o", "--output", choices=["json", "md", "both"], help="Export scan report format (json, md, or both)")
    parser.add_argument("-r", "--recursive", action="store_true", help="Enable recursive HTML link crawler/spider mode")
    
    # Audit modules
    parser.add_argument("--auth-test", action="store_true", help="Run credential validation test against discovered usernames")
    parser.add_argument("--user-file", default="discovered_usernames.txt", help="Path to username file for auth testing")
    parser.add_argument("--pass-file", default="passwords.txt", help="Path to password wordlist file for auth testing")
    parser.add_argument("--vuln-scan", action="store_true", help="Run WooCommerce/WordPress plugin fingerprinting & risk analysis")
    parser.add_argument("--api-fuzz", action="store_true", help="Run WordPress & WooCommerce REST API endpoint fuzzer")
    parser.add_argument("--file-scan", action="store_true", help="Run sensitive file and backup exposure scanner")
    parser.add_argument("--xmlrpc-test", action="store_true", help="Run WordPress XML-RPC endpoint and method availability probe")
    parser.add_argument("--header-scan", action="store_true", help="Run HTTP security headers and transport security audit")
    parser.add_argument("--waf-profile", action="store_true", help="Run WAF rate-limit auto-tune concurrency profiler")
    
    args = parser.parse_args()
    
    reporter = ScanReporter(args.target) if args.output else None
    
    if args.auth_test:
        asyncio.run(run_credential_audit(args.target, args.user_file, args.pass_file, timeout=args.timeout))
        sys.exit(0)
        
    if args.vuln_scan:
        asyncio.run(scan_wordpress_plugins(args.target, timeout=args.timeout, reporter=reporter))
        if reporter:
            if args.output in ["json", "both"]:
                reporter.save_json()
            if args.output in ["md", "both"]:
                reporter.save_markdown()
        sys.exit(0)
        
    if args.api_fuzz:
        asyncio.run(fuzz_api_endpoints(args.target, timeout=args.timeout, reporter=reporter))
        if reporter:
            if args.output in ["json", "both"]:
                reporter.save_json()
            if args.output in ["md", "both"]:
                reporter.save_markdown()
        sys.exit(0)
        
    if args.file_scan:
        asyncio.run(scan_sensitive_files(args.target, timeout=args.timeout, reporter=reporter))
        if reporter:
            if args.output in ["json", "both"]:
                reporter.save_json()
            if args.output in ["md", "both"]:
                reporter.save_markdown()
        sys.exit(0)
        
    if args.xmlrpc_test:
        asyncio.run(test_xmlrpc(args.target, timeout=args.timeout, reporter=reporter))
        if reporter:
            if args.output in ["json", "both"]:
                reporter.save_json()
            if args.output in ["md", "both"]:
                reporter.save_markdown()
        sys.exit(0)
        
    if args.header_scan:
        asyncio.run(scan_security_headers(args.target, timeout=args.timeout, reporter=reporter))
        if reporter:
            if args.output in ["json", "both"]:
                reporter.save_json()
            if args.output in ["md", "both"]:
                reporter.save_markdown()
        sys.exit(0)
        
    if args.waf_profile:
        asyncio.run(profile_waf(args.target, timeout=args.timeout, reporter=reporter))
        if reporter:
            if args.output in ["json", "both"]:
                reporter.save_json()
            if args.output in ["md", "both"]:
                reporter.save_markdown()
        sys.exit(0)
    
    custom_headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                custom_headers[k.strip()] = v.strip()
                
    test_endpoints = load_wordlist(args.wordlist)
    proxy_status = f"{len(PROXY_LIST)} proxies loaded" if PROXY_LIST else "Direct mode (No proxies configured)"
    
    print(f"[*] Initializing Modular Stealth Engine")
    print(f"[*] Target Domain: {args.target}")
    print(f"[*] Wordlist File: {args.wordlist} ({len(test_endpoints)} paths loaded)")
    print(f"[*] Concurrency: {args.concurrency} | Timeout: {args.timeout}s | Recursive Spider: {args.recursive}")
    if custom_headers:
        print(f"[*] Custom Headers Active: {list(custom_headers.keys())}")
    print(f"[*] Network Pool: {proxy_status}\n")
    
    asyncio.run(run_stealth_scanner(
        target_url=args.target, 
        endpoints=test_endpoints, 
        recursive=args.recursive,
        reporter=reporter, 
        concurrency=args.concurrency, 
        timeout=args.timeout, 
        custom_headers=custom_headers
    ))
    
    if reporter:
        if args.output in ["json", "both"]:
            reporter.save_json()
        if args.output in ["md", "both"]:
            reporter.save_markdown()
