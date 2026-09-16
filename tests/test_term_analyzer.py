from __future__ import annotations
from pathlib import Path
import sys
import pytest

from term_analyzer.parser import LogParser, ParsedLog, LogEntry
from term_analyzer.rules import (
    TooManyErrorsRule,
    UnusedDepWarningRule,
    ConfigFileFixRule,
    VulnerableServiceRule,
)

def test_log_parser_classification():
    raw_log = "ERROR: something failed\nWARNING: unused dependency x\nINFO: normal operation"
    parsed = LogParser.parse(iter(raw_log.splitlines()))
    assert len(parsed.errors) == 1
    assert len(parsed.warnings) == 1
    assert len(parsed.infos) == 1

def test_too_many_errors_rule():
    parsed = ParsedLog(
        errors=[LogEntry(raw=f"ERROR: err {i}", kind="error") for i in range(6)]
    )
    rule = TooManyErrorsRule(dry_run=True)
    suggestions = rule.evaluate(parsed)
    assert len(suggestions) == 1
    assert suggestions[0]["rule"] == "TooManyErrorsRule"

def test_config_file_fix_rule(tmp_path: Path):
    cfg = tmp_path / "config.json"
    cfg.write_text('{"debug = true": true}')
    
    parsed = ParsedLog()
    rule = ConfigFileFixRule(cfg, dry_run=False)
    suggestions = rule.evaluate(parsed)
    assert len(suggestions) == 1
    assert suggestions[0]["rule"] == "ConfigFileFixRule"

def test_vulnerable_service_rule():
    parsed = ParsedLog(
        infos=[LogEntry(raw="info: Discovered banner: Server: Apache/2.4.49 (Unix)", kind="info")]
    )
    rule = VulnerableServiceRule(dry_run=True)
    suggestions = rule.evaluate(parsed)
    assert len(suggestions) == 1
    assert "VulnerableServiceRule" in suggestions[0]["rule"]

def test_cli_scan_integration(monkeypatch):
    from term_analyzer.cli import main
    monkeypatch.setattr(sys, "argv", ["term-analyzer", "--scan", "127.0.0.1", "--ports", "80", "--json"])
    exit_code = main()
    assert exit_code == 0
