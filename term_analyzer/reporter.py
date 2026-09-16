import json
import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def json_report(data, filename="term_analyzer_report.json"):
    """Saves report data to a JSON file."""
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    console.print(f"[bold green][+] JSON report saved to {filename}[/bold green]")

def pretty_report(data):
    """Prints a structured rich console report."""
    mode = data.get("mode", "general")
    console.print(Panel(f"[bold cyan]Term Analyzer Report - Mode: {mode.upper()}[/bold cyan]", expand=False))
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Payload / Target", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Length", style="yellow")
    table.add_column("Snippet", style="white")

    results = data.get("results", [])
    for res in results:
        # Handle tuple/list payloads or single strings
        payload_display = ", ".join(str(p) for p in res.get("payloads", [res.get("payload", "")]))
        status = str(res.get("status_code", res.get("status", "N/A")))
        length = str(res.get("response_length", len(res.get("response_snippet", ""))))
        snippet = res.get("response_snippet", "")[:100].replace("\n", " ")
        
        table.add_row(payload_display, status, length, snippet)

    console.print(table)

def generate_html_report(data, filename="term_analyzer_report.html"):
    """Generates an executive HTML security dashboard report."""
    mode = data.get("mode", "intruder").upper()
    fuzz_url = data.get("fuzz_url", data.get("target", "N/A"))
    results = data.get("results", [])

    rows_html = ""
    for res in results:
        payloads = res.get("payloads", [res.get("payload", "")])
        payload_str = " | ".join(str(p) for p in payloads)
        status = res.get("status_code", "N/A")
        length = res.get("response_length", 0)
        snippet = res.get("response_snippet", "").replace("<", "&lt;").replace(">", "&gt;")
        
        badge_class = "badge-success" if str(status).startswith("2") else "badge-warn" if str(status).startswith("3") or str(status).startswith("4") else "badge-error"

        rows_html += f"""
        <tr>
            <td><code>{payload_str}</code></td>
            <td><span class="badge {badge_class}">{status}</span></td>
            <td>{length}</td>
            <td><pre>{snippet}</pre></td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Term Analyzer Security Report</title>
    <style>
        body {{ background-color: #0d1117; color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 20px; }}
        h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
        .card {{ background-color: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 20px; margin-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #30363d; }}
        th {{ background-color: #21262d; color: #e6edf3; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.85em; }}
        .badge-success {{ background-color: #238636; color: #fff; }}
        .badge-warn {{ background-color: #9e6a03; color: #fff; }}
        .badge-error {{ background-color: #da3633; color: #fff; }}
        pre {{ margin: 0; white-space: pre-wrap; word-wrap: break-word; color: #8b949e; max-width: 400px; }}
    </style>
</head>
<body>
    <h1>🛡️ Term Analyzer Security Dashboard</h1>
    <div class="card">
        <h3>Attack Summary</h3>
        <p><strong>Mode:</strong> {mode}</p>
        <p><strong>Target/Endpoint:</strong> <code>{fuzz_url}</code></p>
    </div>
    <div class="card">
        <h3>Execution Results</h3>
        <table>
            <thead>
                <tr>
                    <th>Payloads</th>
                    <th>Status</th>
                    <th>Length</th>
                    <th>Response Snippet</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
    </div>
</body>
</html>
"""
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    console.print(f"[bold green][+] HTML report generated successfully: {filename}[/bold green]")
