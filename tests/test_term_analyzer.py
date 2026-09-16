from __future__ import annotations
from pathlib import Path
from term_analyzer.parser import LogParser, LogEntry
from term_analyzer.rules import TooManyErrorsRule, UnusedDepWarningRule, ConfigFileFixRule

def test_log_parser_classification():
    raw_lines = [
        "INFO: system starting up",
        "ERROR: missing config key timeout",
        "WARNING: unused dependency found",
        "DEBUG: connection pool initialized",
        "Random line without prefix"
    ]
    parsed = LogParser.parse(raw_lines)
    
    assert len(parsed.errors) == 1
    assert parsed.errors[0].message == "missing config key timeout"
    
    assert len(parsed.warnings) == 1
    assert parsed.warnings[0].message == "unused dependency found"
    
    assert len(parsed.infos) == 1
    # Debug lines and un-prefixed lines both land in 'others'
    assert len(parsed.others) == 2

def test_too_many_errors_rule():
    from term_analyzer.parser import ParsedLog
    parsed = ParsedLog(errors=[LogEntry(raw=f"ERROR: fail {i}", kind="error") for i in range(6)])
    
    rule = TooManyErrorsRule(dry_run=True)
    suggestions = rule.evaluate(parsed)
    
    assert len(suggestions) == 1
    assert suggestions[0]["action"] == "fail_ci"
    assert suggestions[0]["severity"] == "high"

def test_config_file_fix_rule(tmp_path: Path):
    config_file = tmp_path / "config.json"
    config_file.write_text('{}')
    
    parsed = LogParser.parse(["ERROR: missing config key db_timeout"])
    rule = ConfigFileFixRule(config_file, dry_run=False)
    
    suggestions = rule.evaluate(parsed)
    assert len(suggestions) == 1
    assert suggestions[0]["key"] == "db_timeout"
    assert suggestions[0]["default"] == 30
    
    import json
    data = json.loads(config_file.read_text())
    assert data["db_timeout"] == 30
