import argparse
import asyncio
import itertools
import os
import aiohttp
from rich.console import Console
from term_analyzer.spraying import load_payload_files, fuzz_advanced
from term_analyzer.reporter import json_report, pretty_report, generate_html_report

console = Console()

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
    
    semaphore = asyncio.Semaphore(args.concurrency)
    pause_lock = asyncio.Lock()
    results = []
    
    async with aiohttp.ClientSession() as session:
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
                pause_lock=pause_lock
            )
            for combo in combinations
        ]
        
        responses = await asyncio.gather(*tasks)
        
    for combo, status, length, text, secrets in responses:
        results.append({
            "payloads": list(combo),
            "status_code": status,
            "response_length": length,
            "response_snippet": text[:150],
            "extracted_secrets": secrets
        })
        
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

def main():
    parser = argparse.ArgumentParser(description="Term Analyzer - Advanced Security Assessment Framework")
    parser.add_argument("--target", type=str, default=None, help="Target URL or IP")
    parser.add_argument("--intruder", action="store_true", help="Enable Burp-style intruder mode")
    parser.add_argument("--intruder-mode", choices=["sniper", "pitchfork", "cluster"], default="sniper", help="Intruder attack mode")
    parser.add_argument("--payloads", type=str, default="payloads.txt", help="Path to payload file(s), comma-separated")
    parser.add_argument("--fuzz-url", type=str, help="URL template with §§ insertion points")
    parser.add_argument("--fuzz-body", type=str, default=None, help="POST/PUT body template with §§ insertion points")
    parser.add_argument("--method", type=str, default="GET", help="HTTP method")
    parser.add_argument("--concurrency", type=int, default=10, help="Max concurrent requests")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between requests")
    parser.add_argument("--rotate-ua", action="store_true", help="Rotate User-Agents")
    parser.add_argument("--smart-pause", action="store_true", help="Pause on 429 rate-limits")
    parser.add_argument("--lockout-str", type=str, default=None, help="String indicating lockout/rate limit")
    parser.add_argument("--pause-duration", type=float, default=15.0, help="Duration to pause on rate-limit")
    parser.add_argument("--json-report", type=str, default=None, help="Save JSON report filename")
    parser.add_argument("--html-report", type=str, default=None, help="Save HTML report filename")

    args = parser.parse_args()
    
    if args.intruder:
        asyncio.run(run_intruder_async(args))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
