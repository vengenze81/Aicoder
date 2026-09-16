"""Command‑line interface – entry point installed as `term-analyzer`."""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import List

from .parser import LogParser
from .reporter import json_report, pretty_report
from .rules import TooManyErrorsRule, UnusedDepWarningRule, ConfigFileFixRule

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
    ]
    if args.config:
        rules.append(ConfigFileFixRule(Path(args.config), dry_run=args.dry_run))
    return rules

def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze terminal output and apply suggested rules.")
    parser.add_argument("input", nargs="?", type=argparse.FileType("r"), default=sys.stdin, help="Log file to parse (default: stdin)")
    parser.add_argument("--config", type=str, help="Path to a JSON config file for patching rules")
    parser.add_argument("--dry-run", action="store_true", default=True, help="Perform a dry run without modifying files (default)")
    parser.add_argument("--apply", dest="dry_run", action="store_false", help="Actually apply changes/side-effects")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity")

    args = parser.parse_args(argv)
    _setup_logging(args.verbose > 0)

    try:
        log.info("Parsing terminal output stream...")
        parsed = LogParser.parse(args.input)
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
        log.error("Fatal error during analysis: %s", exc)
        return 1

if __name__ == "__main__":
    sys.exit(main())
