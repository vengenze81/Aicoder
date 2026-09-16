import json
from pathlib import Path

class RuleEngine:
    def __init__(self, signatures_path: str = "signatures.json"):
        self.signatures_path = Path(signatures_path)
        self.signatures = self.load_signatures()

    def load_signatures(self) -> list[dict]:
        if self.signatures_path.exists():
            try:
                with open(self.signatures_path, "r") as f:
                    return json.load(f)
            except Exception:
                return []
        return []

    def evaluate(self, log_lines: list[str]) -> list[dict]:
        matches = []
        for line in log_lines:
            for sig in self.signatures:
                pattern = sig.get("pattern", "")
                if pattern and pattern.lower() in line.lower():
                    match_info = {
                        "rule_id": sig.get("id", "UNKNOWN"),
                        "service": sig.get("service", "Unknown"),
                        "severity": sig.get("severity", "info"),
                        "cvss": sig.get("cvss", "N/A"),
                        "description": sig.get("description", ""),
                        "action": sig.get("action", "Review configuration."),
                        "matched_line": line
                    }
                    if match_info not in matches:
                        matches.append(match_info)
        return matches
