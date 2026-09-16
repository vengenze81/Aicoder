from __future__ import annotations
import unittest
from pathlib import Path
from term_analyzer.parser import LogParser, ParsedLog, LogEntry
from term_analyzer.rules import TooManyErrorsRule, ConfigFileFixRule, VulnerableServiceRule

def test_log_parser_classification():
    lines = [
        "ERROR: failed to connect",
        "WARNING: deprecated feature",
        "INFO: system startup ok",
        "random debug noise"
    ]
    parsed = LogParser.parse(lines)
    assert len(parsed.errors) == 1
    assert len(parsed.warnings) == 1
    assert len(parsed.infos) == 1
    assert len(parsed.others) == 1

def test_too_many_errors_rule():
    parsed = ParsedLog(
        errors=[LogEntry(raw=f"ERROR: err {i}", kind="error") for i in range(6)]
    )
    rule = TooManyErrorsRule(dry_run=True)
    suggestions = rule.evaluate(parsed)
    assert len(suggestions) == 1
    assert suggestions[0]["rule"] == "TooManyErrors"
    assert suggestions[0]["severity"] == "high"

def test_config_file_fix_rule(tmp_path: Path):
    cfg = tmp_path / "config.json"
    cfg.write_text('{"other": 123}')
    
    parsed = ParsedLog(
        errors=[LogEntry(raw="ERROR: missing config key db_timeout", kind="error")]
    )
    rule = ConfigFileFixRule(cfg, dry_run=False)
    suggestions = rule.evaluate(parsed)
    assert len(suggestions) == 1
    assert suggestions[0]["key"] == "db_timeout"
    assert suggestions[0]["default"] == 30

def test_vulnerable_service_rule():
    parsed = ParsedLog(
        infos=[LogEntry(raw="info: Discovered banner: Server: Apache/2.4.49 (Unix)", kind="info")]
    )
    
    rule = VulnerableServiceRule(dry_run=True)
    suggestions = rule.evaluate(parsed)
    
    assert len(suggestions) == 1
    assert suggestions[0]["rule"] == "VulnerableService"
    assert suggestions[0]["severity"] == "high"
    assert "Apache" in suggestions[0]["message"]

def test_cli_scan_integration(monkeypatch):
    from term_analyzer.cli import main
    import sys
    
    # Mock sys.argv to simulate running `term-analyzer --scan 127.0.0.1 --ports 80 --json`
    monkeypatch.setattr(sys, "argv", ["term-analyzer", "--scan", "127.0.0.1", "--ports", "80", "--json"])
    
    # Run main and expect clean exit (0)
    exit_code = main()
    assert exit_code == 0
