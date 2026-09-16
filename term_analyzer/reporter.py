from __future__ import annotations
import json
from typing import Any, List, Mapping

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

def json_report(suggestions: List[Mapping[str, Any]]) -> str:
    return json.dumps(suggestions, indent=2, sort_keys=True)

def pretty_report(suggestions: List[Mapping[str, Any]]) -> str:
    if not suggestions:
        if HAS_RICH:
            console = Console()
            console.print(Panel("✅ No security issues or rule violations detected.", style="green bold", title="Scan Results"))
            return ""
        return "✅ No issues detected."

    if not HAS_RICH:
        # Fallback to plain text if rich is missing
        lines = ["🔎 Analysis Summary:"]
        for s in suggestions:
            sev = s.get("severity", "unknown").upper()
            lines.append(f"- [{sev}] {s.get('message')}")
            if "action" in s:
                lines.append(f"    ↳ Action: {s['action']}")
        return "\n".join(lines)

    # Rich-powered formatted table and output
    console = Console()
    table = Table(title="🛡️ Security & Analysis Report", show_header=True, header_style="bold magenta", expand=True)
    table.add_column("Severity", style="bold", width=10, justify="center")
    table.add_column("Rule", style="cyan", width=18)
    table.add_column("Message & Finding", style="white")
    table.add_column("Recommended Action", style="yellow", width=20)

    for s in suggestions:
        sev = s.get("severity", "unknown").lower()
        if sev == "high":
            sev_badge = Text("HIGH", style="bold white on red")
        elif sev == "medium":
            sev_badge = Text("MEDIUM", style="bold black on yellow")
        else:
            sev_badge = Text(sev.upper(), style="bold black on cyan")

        rule_name = s.get("rule", "Unknown")
        message = s.get("message", "")
        action = s.get("action", "N/A")

        table.add_row(sev_badge, rule_name, message, action)

    console.print(table)
    return ""
