import argparse
import json
import time
from term_analyzer.scanner import expand_targets, scan_target_ports
from term_analyzer.spraying import run_credential_spray

def main():
    parser = argparse.ArgumentParser(description="Term Analyzer: Automated Network & Credential Auditor")
    parser.add_argument("--target", required=True, help="Target IP, hostname, or CIDR subnet")
    parser.add_argument("--ports", default="21,22,23,80,443,3306,5432,8080", help="Comma-separated list of ports to check")
    parser.add_argument("--spray", action="store_true", help="Automatically scan and run credential spray on open ports")
    parser.add_argument("--user", default=None, help="Custom username(s) separated by commas")
    parser.add_argument("--password", default=None, help="Custom password to spray")
    parser.add_argument("--user-file", default=None, help="Path to a text file containing usernames")
    parser.add_argument("--password-file", default=None, help="Path to a text file containing passwords")
    parser.add_argument("--threads", type=int, default=5, help="Number of concurrent threads (default: 5)")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay in seconds between request attempts (rate-limiting)")
    parser.add_argument("--header", action="append", help="Custom HTTP header in 'Key: Value' format")
    parser.add_argument("--output", default=None, help="Path to save results as a JSON report file")

    args = parser.parse_args()

    start_time = time.time()
    target_ports = [int(p.strip()) for p in args.ports.split(",")]
    resolved_targets = expand_targets(args.target)
    
    print(f"[*] Target scope expanded: {len(resolved_targets)} host(s) queued.")
    print(f"[*] Target ports: {target_ports}")

    all_audit_results = []
    hosts_scanned = 0
    total_open_ports = 0

    for host in resolved_targets:
        print(f"\n[*] Processing target: {host}")
        hosts_scanned += 1
        open_ports = scan_target_ports(host, target_ports)
        
        if not open_ports:
            print(f"    [-] No open ports discovered on {host}.")
            continue
            
        total_open_ports += len(open_ports)
        print(f"    [+] Discovered open ports on {host}: {open_ports}")

        if args.spray:
            print(f"    [*] Initiating multithreaded credential spray on {host}...")
            host_results = run_credential_spray(
                target_host=host,
                open_ports=open_ports,
                user_arg=args.user,
                password_arg=args.password,
                user_file=args.user_file,
                password_file=args.password_file,
                max_threads=args.threads,
                delay=args.delay,
                custom_headers=args.header
            )
            all_audit_results.extend(host_results)

    elapsed_time = time.time() - start_time
    successful_logins = [r for r in all_audit_results if r.get("success")]

    print("\n" + "="*50)
    print("                 AUDIT SUMMARY DASHBOARD                 ")
    print("="*50)
    print(f" Hosts Scanned         : {hosts_scanned}")
    print(f" Open Ports Found      : {total_open_ports}")
    print(f" Credential Checks Run : {len(all_audit_results)}")
    print(f" Successful Logins     : {len(successful_logins)}")
    print(f" Total Elapsed Time    : {elapsed_time:.2f} seconds")
    print("="*50)

    if args.output and all_audit_results:
        with open(args.output, "w") as f:
            json.dump(all_audit_results, f, indent=4)
        print(f"[+] Full audit report successfully saved to {args.output}")

if __name__ == "__main__":
    main()
