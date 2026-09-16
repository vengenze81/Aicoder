"""Command‑line interface – entry point installed as `term-analyzer`."""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import List

from .parser import LogParser, ParsedLog, LogEntry
from .reporter import json_report, pretty_report
from .rules import TooManyErrorsRule, UnusedDepWarningRule, ConfigFileFixRule, VulnerableServiceRule

try:
    from tester import PortTester
except ImportError:
    PortTester = None

log = logging.getLogger(__name__)

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s – %(message)s",
        datefmt="%H:%M:%S",
    )

def build_rule_set(args: argparse.Namespace) -> List:
    """Instantiate rule objects based on CLI flags."""
    rules = [
        TooManyErrorsRule(dry_run=args.dry_run),
        UnusedDepWarningRule(dry_run=args.dry_run),
        VulnerableServiceRule(dry_run=args.dry_run),
    ]
    if args.config:
        rules.append(ConfigFileFixRule(Path(args.config), dry_run=args.dry_run))
    return rules

async def perform_scan_async(target: str, ports_str: str) -> ParsedLog:
    """Actively and concurrently scan a target IP, CIDR subnet, or local interface using asyncio."""
    if not PortTester:
        raise RuntimeError("PortTester module (`tester.py`) could not be imported.")

    # Handle automatic local network discovery
    if target.lower() == "local":
        from tester import discover_local_interfaces
        interfaces = discover_local_interfaces()
        non_loopback = [ip for ip in interfaces if not ip.startswith("127.")]
        if non_loopback:
            base_ip = non_loopback[0]
            parts = base_ip.split(".")
            if len(parts) == 4:
                target = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            else:
                target = base_ip
        else:
            target = "127.0.0.1"
        print(f"[*] Auto-resolved local scan target to: {target}")
    if not PortTester:
        raise RuntimeError("PortTester module (`tester.py`) could not be imported.")
    
    ports = [int(p.strip()) for p in ports_str.split(",") if p.strip().isdigit()]
    parsed = ParsedLog()
    
    tester = PortTester(target)
    log.info("Starting concurrent async reconnaissance scan on %s across ports: %s", target, ports)
    
    services = await tester.scan_subnet(target, ports)
    
    for service in services:
        if service.status == "open":
            msg = f"Discovered open port {service.port} with banner: {service.banner or 'No banner'}"
            if service.version:
                msg += f" (Identified version: {service.version})"
            entry = LogEntry(raw=f"info: {msg}", kind="info")
            parsed.infos.append(entry)
        else:
            log.debug("Port %s is closed or filtered.", service.port)
            
    return parsed

def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze terminal output or perform active security reconnaissance.")
    parser.add_argument("input", nargs="?", type=argparse.FileType("r"), default=None, help="Log file to parse (default: stdin if not scanning)")
    parser.add_argument("--scan", type=str, metavar="TARGET", help="Perform active reconnaissance scan on target IP/hostname")
    parser.add_argument("--ports", type=str, default="21,22,25,80,443,3306,8080", help="Comma-separated list of ports to scan (used with --scan)")
    parser.add_argument("--config", type=str, help="Path to a JSON config file for patching rules")
    parser.add_argument("--dry-run", action="store_true", default=True, help="Perform a dry run without modifying files (default)")
    parser.add_argument("--apply", dest="dry_run", action="store_false", help="Actually apply changes/side-effects")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity")

    args = parser.parse_args(argv)
    _setup_logging(args.verbose > 0)

    try:
        if args.scan:
            parsed = asyncio.run(perform_scan_async(args.scan, args.ports))
        else:
            log.info("Parsing terminal output stream...")
            source = args.input if args.input is not None else sys.stdin
            parsed = LogParser.parse(source)

        rules = build_rule_set(args)
        suggestions = []
        for rule in rules:
            suggestions.extend(rule.evaluate(parsed))

        if args.json:
            print(json_report(suggestions))
        else:
            print(pretty_report(suggestions))

        return 0
    except Exception as exc:
        log.error("Fatal error during analysis/recon: %s", exc)
        return 1

if __name__ == "__main__":
    sys.exit(main())
