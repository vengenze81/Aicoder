import argparse
import asyncio
import itertools
import os
import aiohttp
from aiohttp_socks import ProxyConnector
from rich.console import Console
from term_analyzer.spraying import load_payload_files, fuzz_advanced
from term_analyzer.reporter import json_report, pretty_report, generate_html_report
from term_analyzer.templates import run_template_scan
from term_analyzer.jwt_utils import decode_jwt, brute_force_jwt, download_wordlist
from term_analyzer.vhost import run_vhost_scan
from term_analyzer.dir_scanner import run_dir_scan
from term_analyzer.openapi_scanner import run_openapi_scan
from term_analyzer.crawler import crawl_target

console = Console()

def parse_key_value_pairs(kv_list, delimiter):
    parsed_dict = {}
    if not kv_list:
        return parsed_dict
    for item in kv_list:
        if delimiter in item:
            k, v = item.split(delimiter, 1)
            parsed_dict[k.strip()] = v.strip()
    return parsed_dict

async def run_intruder_async(args):
    payload_lists = load_payload_files(args.payloads)
    mode = getattr(args, "intruder_mode", "sniper")
    
    if mode == "pitchfork":
        combinations = list(zip(*payload_lists))
    elif mode == "cluster":
        combinations = list(itertools.product(*payload_lists))
    else:
        combinations = [(p,) for p in payload_lists[0]]
        
    console.print(f"[bold cyan][*] Loaded {len(combinations)} payload combinations for mode: {mode.upper()}[/bold cyan]")
    
    exclude_statuses = {int(s.strip()) for s in args.exclude_status.split(",")} if args.exclude_status else set()
    exclude_lengths = {int(l.strip()) for l in args.exclude_length.split(",")} if args.exclude_length else set()
    
    custom_headers = parse_key_value_pairs(args.header, ":")
    custom_cookies = parse_key_value_pairs(args.cookie, "=")
    
    semaphore = asyncio.Semaphore(args.concurrency)
    pause_lock = asyncio.Lock()
    results = []
    filtered_count = 0
    
    connector = ProxyConnector.from_url(args.proxy) if args.proxy else None
    
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            fuzz_advanced(
                session=session,
                method=args.method,
                url_template=args.fuzz_url,
                body_template=args.fuzz_body,
                payload_tuple=combo,
                semaphore=semaphore,
                delay=args.delay,
                rotate_ua=args.rotate_ua,
                smart_pause=args.smart_pause,
                lockout_str=args.lockout_str,
                pause_duration=args.pause_duration,
                pause_lock=pause_lock,
                custom_headers=custom_headers,
                custom_cookies=custom_cookies
            )
            for combo in combinations
        ]
        
        responses = await asyncio.gather(*tasks)
        
    for combo, status, length, text, secrets in responses:
        if status in exclude_statuses or length in exclude_lengths:
            filtered_count += 1
            continue
            
        results.append({
            "payloads": list(combo),
            "status_code": status,
            "response_length": length,
            "response_snippet": text[:150],
            "extracted_secrets": secrets
        })
        
    if filtered_count > 0:
        console.print(f"[dim][*] Filtered out {filtered_count} uninteresting response(s) based on your criteria.[/dim]")
        
    report_data = {
        "mode": "intruder",
        "intruder_mode": mode,
        "fuzz_url": args.fuzz_url,
        "results": results
    }
    
    if args.json_report:
        json_report(report_data, args.json_report)
    if args.html_report:
        generate_html_report(report_data, args.html_report)
        
    pretty_report(report_data)

async def run_template_async(args):
    results = await run_template_scan(args.target, args.template, args.concurrency, proxy=args.proxy)
    
    formatted_results = []
    for r in results:
        if r["matched"]:
            console.print(f"[bold green][MATCH] [{r['severity'].upper()}] {r['name']} -> {r['url']} (Status: {r['status_code']})[/bold green]")
        else:
            console.print(f"[dim][-] No match: {r['name']} -> {r['url']} (Status: {r['status_code']})[/dim]")
            
        formatted_results.append({
            "payloads": [r["url"]],
            "status_code": r["status_code"],
            "response_length": len(r["response_snippet"]),
            "response_snippet": r["response_snippet"],
            "extracted_secrets": []
        })
        
    report_data = {
        "mode": "template-scan",
        "target": args.target,
        "results": formatted_results
    }
    
    if args.json_report:
        json_report(report_data, args.json_report)
    if args.html_report:
        generate_html_report(report_data, args.html_report)

async def run_vhost_async(args):
    if not args.domain:
        console.print("[bold red][!] Please specify a base domain using --domain (e.g., example.com)[/bold red]")
        return
        
    exclude_statuses = {int(s.strip()) for s in args.exclude_status.split(",")} if args.exclude_status else set()
    exclude_lengths = {int(l.strip()) for l in args.exclude_length.split(",")} if args.exclude_length else set()
    
    results = await run_vhost_scan(
        target_url=args.target,
        base_domain=args.domain,
        wordlist_path=args.wordlist,
        concurrency=args.concurrency,
        proxy=args.proxy,
        exclude_statuses=exclude_statuses,
        exclude_lengths=exclude_lengths
    )
    
    report_data = {
        "mode": "vhost-scan",
        "target": args.target,
        "domain": args.domain,
        "results": results
    }
    
    if args.json_report:
        json_report(report_data, args.json_report)
    if args.html_report:
        generate_html_report(report_data, args.html_report)

async def run_dir_scan_async(args):
    if not args.target:
        console.print("[bold red][!] Please specify a target URL using --target[/bold red]")
        return
        
    exclude_statuses = {int(s.strip()) for s in args.exclude_status.split(",")} if args.exclude_status else {404}
    exclude_lengths = {int(l.strip()) for l in args.exclude_length.split(",")} if args.exclude_length else set()
    
    custom_headers = parse_key_value_pairs(args.header, ":")
    custom_cookies = parse_key_value_pairs(args.cookie, "=")
    
    results = await run_dir_scan(
        target_url=args.target,
        wordlist_path=args.wordlist,
        concurrency=args.concurrency,
        proxy=args.proxy,
        exclude_statuses=exclude_statuses,
        exclude_lengths=exclude_lengths,
        custom_headers=custom_headers,
        custom_cookies=custom_cookies
    )
    
    report_data = {
        "mode": "dir-scan",
        "target": args.target,
        "results": results
    }
    
    if args.json_report:
        json_report(report_data, args.json_report)
    if args.html_report:
        generate_html_report(report_data, args.html_report)

async def run_openapi_async(args):
    if not args.target or not args.spec:
        console.print("[bold red][!] Please specify both --target and --spec <file.json/yaml>[/bold red]")
        return
        
    custom_headers = parse_key_value_pairs(args.header, ":")
    custom_cookies = parse_key_value_pairs(args.cookie, "=")
    
    results = await run_openapi_scan(
        base_url=args.target,
        spec_path=args.spec,
        custom_headers=custom_headers,
        custom_cookies=custom_cookies,
        concurrency=args.concurrency
    )
    
    report_data = {
        "mode": "openapi-scan",
        "target": args.target,
        "spec": args.spec,
        "results": results
    }
    
    if args.json_report:
        json_report(report_data, args.json_report)
    if args.html_report:
        generate_html_report(report_data, args.html_report)

async def run_crawl_async(args):
    if not args.target:
        console.print("[bold red][!] Please specify a target URL using --target[/bold red]")
        return
        
    endpoints, forms = await crawl_target(
        target_url=args.target,
        max_depth=args.max_depth,
        concurrency=args.concurrency
    )
    
    formatted_results = []
    for ep in endpoints:
        formatted_results.append({
            "payloads": [ep["url"]],
            "status_code": ep["status"],
            "response_length": 0,
            "response_snippet": f"Depth: {ep['depth']}",
            "extracted_secrets": ep["secrets"]
        })
        
    report_data = {
        "mode": "crawl-scan",
        "target": args.target,
        "results": formatted_results
    }
    
    if args.json_report:
        json_report(report_data, args.json_report)
    if args.html_report:
        generate_html_report(report_data, args.html_report)

def handle_jwt_commands(args):
    if args.jwt_inspect:
        header, payload, err = decode_jwt(args.jwt_inspect)
        if err:
            console.print(f"[bold red][!] Error decoding JWT: {err}[/bold red]")
            return
        console.print("[bold green]=== JWT Header ===[/bold green]")
        console.print(header)
        console.print("[bold green]=== JWT Payload ===[/bold green]")
        console.print(payload)

    if args.jwt_brute:
        if not args.wordlist:
            console.print("[bold red][!] Please specify a wordlist using --wordlist for JWT brute-forcing.[/bold red]")
            return
        secret = asyncio.run(brute_force_jwt(args.jwt_brute, args.wordlist))
        if secret:
            console.print(f"[bold green][+] SUCCESS! Found weak JWT secret: {secret}[/bold green]")
        else:
            console.print("[bold yellow][-] Secret not found in wordlist.[/bold yellow]")

def main():
    parser = argparse.ArgumentParser(description="Term Analyzer - Advanced Security Assessment Framework")
    parser.add_argument("--target", type=str, default=None, help="Target URL or IP")
    parser.add_argument("--intruder", action="store_true", help="Enable Burp-style intruder mode")
    parser.add_argument("--vhost", action="store_true", help="Enable Virtual Host / Host header fuzzing mode")
    parser.add_argument("--dir-scan", action="store_true", help="Enable directory and file brute-forcing mode")
    parser.add_argument("--openapi", action="store_true", help="Enable OpenAPI / Swagger schema-driven scan mode")
    parser.add_argument("--crawl", action="store_true", help="Enable recursive web crawler and form extractor mode")
    parser.add_argument("--max-depth", type=int, default=2, help="Maximum crawl depth")
    parser.add_argument("--spec", type=str, default=None, help="Path to OpenAPI/Swagger JSON or YAML spec file")
    parser.add_argument("--domain", type=str, default=None, help="Base domain for VHost fuzzing (e.g., example.com)")
    parser.add_argument("--intruder-mode", choices=["sniper", "pitchfork", "cluster"], default="sniper", help="Intruder attack mode")
    parser.add_argument("--payloads", type=str, default="payloads.txt", help="Path to payload file(s), comma-separated")
    parser.add_argument("--fuzz-url", type=str, help="URL template with §§ insertion points")
    parser.add_argument("--fuzz-body", type=str, default=None, help="POST/PUT body template with §§ insertion points")
    parser.add_argument("--template", type=str, default=None, help="Path to YAML template file or directory")
    parser.add_argument("--jwt-inspect", type=str, default=None, help="Inspect and decode a JWT token")
    parser.add_argument("--jwt-brute", type=str, default=None, help="Brute-force HS256 JWT secret using a wordlist")
    parser.add_argument("--download-wordlist", choices=["jwt", "directories", "parameters", "subdomains"], default=None, help="Download standard wordlists")
    parser.add_argument("--wordlist", type=str, default="subdomains.txt", help="Path to wordlist file")
    parser.add_argument("--proxy", type=str, default=None, help="Upstream proxy URL (e.g., http://127.0.0.1:8080 or socks5://127.0.0.1:9050)")
    parser.add_argument("--header", action="append", help="Custom header in 'Key:Value' format (can be used multiple times)")
    parser.add_argument("--cookie", action="append", help="Custom cookie in 'Name=Value' format (can be used multiple times)")
    parser.add_argument("--method", type=str, default="GET", help="HTTP method")
    parser.add_argument("--concurrency", type=int, default=20, help="Max concurrent requests")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between requests")
    parser.add_argument("--rotate-ua", action="store_true", help="Rotate User-Agents")
    parser.add_argument("--smart-pause", action="store_true", help="Pause on 429 rate-limits")
    parser.add_argument("--lockout-str", type=str, default=None, help="String indicating lockout/rate limit")
    parser.add_argument("--pause-duration", type=float, default=15.0, help="Duration to pause on rate-limit")
    parser.add_argument("--exclude-status", type=str, default=None, help="Comma-separated status codes to exclude (e.g., 404,403)")
    parser.add_argument("--exclude-length", type=str, default=None, help="Comma-separated response lengths to exclude (e.g., 9,120)")
    parser.add_argument("--json-report", type=str, default=None, help="Save JSON report filename")
    parser.add_argument("--html-report", type=str, default=None, help="Save HTML report filename")

    args = parser.parse_args()
    
    if args.download_wordlist:
        download_wordlist(args.download_wordlist)
    elif args.crawl:
        asyncio.run(run_crawl_async(args))
    elif args.openapi:
        asyncio.run(run_openapi_async(args))
    elif args.dir_scan:
        asyncio.run(run_dir_scan_async(args))
    elif args.vhost:
        asyncio.run(run_vhost_async(args))
    elif args.intruder:
        asyncio.run(run_intruder_async(args))
    elif args.template and args.target:
        asyncio.run(run_template_async(args))
    elif args.jwt_inspect or args.jwt_brute:
        handle_jwt_commands(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
