import sys
import asyncio
import argparse
from engine import run_stealth_scanner
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
    parser = argparse.ArgumentParser(description="Modular Asynchronous Stealth Security Reconnaissance Engine")
    parser.add_argument("target", help="Target base URL (e.g., https://example.com)")
    parser.add_argument("-w", "--wordlist", default="wordlist.txt", help="Path to endpoint wordlist file (default: wordlist.txt)")
    parser.add_argument("-c", "--concurrency", type=int, default=5, help="Maximum concurrent requests (default: 5)")
    parser.add_argument("-t", "--timeout", type=float, default=8.0, help="Request timeout in seconds (default: 8.0)")
    parser.add_argument("-H", "--header", action="append", help="Custom header in 'Key: Value' format")
    parser.add_argument("-o", "--output", choices=["json", "md", "both"], help="Export scan report format (json, md, or both)")
    parser.add_argument("-r", "--recursive", action="store_true", help="Enable recursive HTML link crawler/spider mode")
    
    args = parser.parse_args()
    
    custom_headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                custom_headers[k.strip()] = v.strip()
                
    test_endpoints = load_wordlist(args.wordlist)
    proxy_status = f"{len(PROXY_LIST)} proxies loaded" if PROXY_LIST else "Direct mode (No proxies configured)"
    
    reporter = ScanReporter(args.target) if args.output else None
    
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
