from __future__ import annotations
import abc
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List
from .parser import ParsedLog, LogEntry

log = logging.getLogger(__name__)

class Rule(abc.ABC):
    name: str
    def __init__(self, *, dry_run: bool = True) -> None:
        self.dry_run = dry_run

    @abc.abstractmethod
    def evaluate(self, parsed: ParsedLog) -> List[Dict[str, Any]]:
        pass

    def apply(self, suggestion: Dict[str, Any]) -> None:
        if self.dry_run:
            log.info("[DRY-RUN] %s – %s", self.name, json.dumps(suggestion))
        else:
            log.debug("[APPLY] %s – %s", self.name, json.dumps(suggestion))

class TooManyErrorsRule(Rule):
    name = "TooManyErrors"
    THRESHOLD = 5

    def evaluate(self, parsed: ParsedLog) -> List[Dict[str, Any]]:
        count = len(parsed.errors)
        if count <= self.THRESHOLD:
            return []
        suggestion = {
            "rule": self.name,
            "severity": "high",
            "message": f"{count} errors detected (threshold={self.THRESHOLD})",
            "action": "fail_ci",
        }
        self.apply(suggestion)
        return [suggestion]

class UnusedDepWarningRule(Rule):
    name = "UnusedDepWarning"
    _PATTERN = re.compile(r"unused\s+dependency", re.IGNORECASE)

    def evaluate(self, parsed: ParsedLog) -> List[Dict[str, Any]]:
        matches = [e for e in parsed.warnings if self._PATTERN.search(e.message)]
        if not matches:
            return []
        suggestion = {
            "rule": self.name,
            "severity": "medium",
            "message": f"Found {len(matches)} unused-dependency warnings",
            "action": "run_dep_prune",
        }
        self.apply(suggestion)
        return [suggestion]

class ConfigFileFixRule(Rule):
    name = "ConfigFileFix"
    _MISSING_KEY_RE = re.compile(r"missing\s+config\s+key\s+([A-Za-z0-9_.-]+)", re.IGNORECASE)

    def __init__(self, config_path: Path, *, dry_run: bool = True) -> None:
        super().__init__(dry_run=dry_run)
        self.config_path = config_path

    def evaluate(self, parsed: ParsedLog) -> List[Dict[str, Any]]:
        suggestions = []
        for entry in parsed.errors:
            m = self._MISSING_KEY_RE.search(entry.message)
            if not m:
                continue
            key = m.group(1)
            suggestion = {
                "rule": self.name,
                "severity": "low",
                "message": f"Add default for missing config key `{key}`",
                "action": "patch_config",
                "key": key,
                "default": self._default_for(key),
            }
            self.apply(suggestion)
            suggestions.append(suggestion)
        return suggestions

    @staticmethod
    def _default_for(key: str) -> Any:
        if key.lower().endswith("path"):
            return "/tmp"
        if key.lower().endswith("timeout"):
            return 30
        return ""

    def apply(self, suggestion: Dict[str, Any]) -> None:
        if self.dry_run:
            super().apply(suggestion)
            return
        try:
            data = json.loads(self.config_path.read_text())
        except json.JSONDecodeError as exc:
            log.error("Cannot parse config %s: %s", self.config_path, exc)
            return
        key = suggestion["key"]
        data[key] = suggestion["default"]
        self.config_path.write_text(json.dumps(data, indent=2))
        log.info("Patched %s – set %s = %r", self.config_path, key, suggestion["default"])

class VulnerableServiceRule(Rule):
    name = "VulnerableService"
    
    _VULN_PATTERNS = [
        (re.compile(r"Apache[/\s](2\.4\.49|2\.4\.50)", re.IGNORECASE), "CVE-2021-41773: Apache Path Traversal"),
        (re.compile(r"OpenSSH[_\s]([0-7]\.|8\.[01])", re.IGNORECASE), "Outdated OpenSSH version with potential vulnerabilities"),
    ]

    def evaluate(self, parsed: ParsedLog) -> List[Dict[str, Any]]:
        suggestions = []
        for entry in parsed.all_entries():
            for pattern, vuln_desc in self._VULN_PATTERNS:
                if pattern.search(entry.message):
                    suggestion = {
                        "rule": self.name,
                        "severity": "high",
                        "message": f"Vulnerable service detected: {vuln_desc} found in message: '{entry.message}'",
                        "action": "flag_security_risk",
                    }
                    self.apply(suggestion)
                    suggestions.append(suggestion)
                    break
        return suggestions
