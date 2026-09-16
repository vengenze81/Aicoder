from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, List, Mapping

from .parser import ParsedLog

log = logging.getLogger(__name__)

class BaseRule:
    def __init__(self, dry_run: bool = True) -> None:
        self.dry_run = dry_run

    def evaluate(self, parsed: ParsedLog) -> List[Mapping[str, Any]]:
        raise NotImplementedError

class TooManyErrorsRule(BaseRule):
    """Detects if error log count exceeds a safety threshold."""
    def evaluate(self, parsed: ParsedLog) -> List[Mapping[str, Any]]:
        error_count = len(parsed.errors)
        if error_count > 5:
            return [{
                "rule": "TooManyErrorsRule",
                "severity": "high",
                "message": f"Found {error_count} error entries in log stream.",
                "action": "Investigate underlying error logs and stack traces."
            }]
        return []

class UnusedDepWarningRule(BaseRule):
    """Detects unused dependency warnings in logs."""
    def evaluate(self, parsed: ParsedLog) -> List[Mapping[str, Any]]:
        suggestions = []
        for entry in parsed.warnings:
            if "unused dependency" in entry.raw.lower():
                suggestions.append({
                    "rule": "UnusedDepWarningRule",
                    "severity": "low",
                    "message": f"Unused dependency warning detected: {entry.raw}",
                    "action": "Remove unused dependency from project configuration."
                })
        return suggestions

class ConfigFileFixRule(BaseRule):
    """Automatically patches or suggests fixes in configuration files."""
    def __init__(self, config_path: Path, dry_run: bool = True) -> None:
        super().__init__(dry_run=dry_run)
        self.config_path = config_path

    def evaluate(self, parsed: ParsedLog) -> List[Mapping[str, Any]]:
        suggestions = []
        if not self.config_path.exists():
            return suggestions

        try:
            content = self.config_path.read_text(encoding="utf-8")
            if "debug = true" in content.lower():
                suggestions.append({
                    "rule": "ConfigFileFixRule",
                    "severity": "medium",
                    "message": f"Debug mode enabled in config file: {self.config_path}",
                    "action": "Set debug = false for production deployment."
                })
        except Exception as exc:
            log.error("Failed to read config file %s: %s", self.config_path, exc)

        return suggestions

class VulnerableServiceRule(BaseRule):
    """Detects known vulnerable service versions using external JSON signatures."""
    def __init__(self, dry_run: bool = True, sig_path: str | Path = "signatures.json") -> None:
        super().__init__(dry_run=dry_run)
        self.sig_path = Path(sig_path)
        self.signatures = self._load_signatures()

    def _load_signatures(self) -> List[dict]:
        path = self.sig_path
        if not path.exists():
            # Fallback path relative to package root if not in cwd
            alt_path = Path(__file__).parent.parent / "signatures.json"
            if alt_path.exists():
                path = alt_path
            else:
                log.warning("Signatures file not found at %s or %s", self.sig_path, alt_path)
                return []
        
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                log.info("Loaded %d vulnerability signatures from %s", len(data), path)
                return data
        except Exception as exc:
            log.error("Failed to load signatures from %s: %s", path, exc)
            return []

    def evaluate(self, parsed: ParsedLog) -> List[Mapping[str, Any]]:
        suggestions = []
        all_entries = parsed.all_entries()

        for sig in self.signatures:
            pattern = sig.get("pattern")
            if not pattern:
                continue
            
            compiled_regex = re.compile(pattern, re.IGNORECASE)
            for entry in all_entries:
                if compiled_regex.search(entry.raw):
                    suggestions.append({
                        "rule": f"VulnerableServiceRule ({sig.get('id', 'CVE')})",
                        "severity": sig.get("severity", "high"),
                        "message": sig.get("message", "Vulnerable service detected."),
                        "action": sig.get("action", "Update service immediately.")
                    })
                    break  # Trigger once per signature match

        return suggestions
