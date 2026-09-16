import argparse
import json
from term_analyzer.scanner import expand_targets, scan_target_ports
from term_analyzer.spraying import run_credential_spray

def main():
    parser = argparse.ArgumentParser(description="Term Analyzer: Automated Network & Credential Auditor")
    parser.add_argument("--target", required=True, help="Target IP, hostname, or CIDR subnet")
    parser.add_argument("--ports", default="21,22,23,80,443,3306,5432,8080", help="Comma-separated list of ports to check")
    parser.add_argument("--spray", action="store_true", help="Automatically scan and run credential spray on open ports")
    parser.add_argument("--user", default=None, help="Custom username(s) separated by commas")
    parser.add_argument("--password", default=None, help="Custom password to spray")
    parser.add_argument("--user-file", default=None, help="Path to a text file containing usernames (one per line)")
    parser.add_argument("--password-file", default=None, help="Path to a text file containing passwords (one per line)")
    parser.add_argument("--threads", type=int, default=5, help="Number of concurrent threads for spraying (default: 5)")
    parser.add_argument("--output", default=None, help="Path to save results as a JSON report file")

    args = parser.parse_args()

    target_ports = [int(p.strip()) for p in args.ports.split(",")]
    resolved_targets = expand_targets(args.target)
    print(f"[*] Expanded target scope: {len(resolved_targets)} host(s) to process.")

    all_audit_results = []

    for host in resolved_targets:
        print(f"\n[*] Processing target: {host}")
        open_ports = scan_target_ports(host, target_ports)
        
        if not open_ports:
            print(f"    [-] No open ports discovered on {host}.")
            continue
            
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
                max_threads=args.threads
            )
            all_audit_results.extend(host_results)

    if args.output and all_audit_results:
        with open(args.output, "w") as f:
            json.dump(all_audit_results, f, indent=4)
        print(f"\n[+] Full audit report successfully saved to {args.output}")

if __name__ == "__main__":
    main()
