import argparse
import json
from term_analyzer.scanner import scan_target_ports
from term_analyzer.spraying import run_credential_spray

def main():
    parser = argparse.ArgumentParser(description="Term Analyzer: Automated Network & Credential Auditor")
    parser.add_argument("--target", required=True, help="Target IP address or hostname")
    parser.add_argument("--ports", default="21,22,23,80,443,3306,5432,8080", help="Comma-separated list of ports to check")
    parser.add_argument("--spray", action="store_true", help="Automatically scan and run default credential spray on open ports")
    parser.add_argument("--user", default=None, help="Custom username(s) separated by commas")
    parser.add_argument("--password", default=None, help="Custom password to spray")
    parser.add_argument("--output", default=None, help="Path to save results as a JSON report file (e.g., results.json)")

    args = parser.parse_args()

    target_ports = [int(p.strip()) for p in args.ports.split(",")]
    print(f"[*] Target acquired: {args.target}")

    spray_results = []
    if args.spray:
        open_ports = scan_target_ports(args.target, target_ports)
        if not open_ports:
            print("[-] No open ports discovered from the provided list. Skipping spray.")
            return
            
        print(f"[*] Discovered open ports for spraying: {open_ports}")
        print("[*] Initiating automated credential spray...")
        spray_results = run_credential_spray(
            target_host=args.target,
            open_ports=open_ports,
            user_arg=args.user,
            password_arg=args.password
        )
    else:
        open_ports = scan_target_ports(args.target, target_ports)
        print(f"[*] Scan complete. Open ports: {open_ports}")

    if args.output and spray_results:
        with open(args.output, "w") as f:
            json.dump(spray_results, f, indent=4)
        print(f"[+] Report successfully saved to {args.output}")

if __name__ == "__main__":
    main()
