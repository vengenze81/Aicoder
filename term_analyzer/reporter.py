from __future__ import annotations
import json
from typing import Any, List, Mapping

def json_report(suggestions: List[Mapping[str, Any]]) -> str:
    return json.dumps(suggestions, indent=2, sort_keys=True)

def pretty_report(suggestions: List[Mapping[str, Any]]) -> str:
    if not suggestions:
        return "✅ No issues detected."
    lines = ["🔎 Analysis Summary:"]
    for s in suggestions:
        sev = s.get("severity", "unknown").upper()
        lines.append(f"- [{sev}] {s.get('message')}")
        if "action" in s:
            lines.append(f"    ↳ Action: {s['action']}")
    return "\n".join(lines)
