from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Input, Button, DataTable, RichLog, Checkbox, Static
from textual.containers import Container, Horizontal, Vertical
import asyncio
from pathlib import Path
from term_analyzer.rules import RuleEngine
from tester import PortTester, discover_local_interfaces

class TermAnalyzerTUI(App):
    CSS = """
    Screen {
        background: #0f172a;
        color: #e2e8f0;
    }
    #sidebar {
        width: 38%;
        background: #1e293b;
        padding: 1;
        border-right: heavy #38bdf8;
    }
    #main-content {
        width: 62%;
        padding: 1;
    }
    Input {
        margin-bottom: 1;
    }
    Checkbox {
        margin-bottom: 1;
    }
    Button {
        width: 100%;
        background: #38bdf8;
        color: #0f172a;
        text-style: bold;
        margin-top: 1;
        margin-bottom: 1;
    }
    Button:hover {
        background: #7dd3fc;
    }
    DataTable {
        height: 45%;
        margin-bottom: 1;
        background: #0f172a;
        border: solid #334155;
    }
    RichLog {
        height: 45%;
        background: #090d16;
        border: solid #334155;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Static("[bold cyan]🛡️ Target Configuration[/bold cyan]\n")
                yield Static("Target IP / CIDR / 'local':")
                yield Input(value="127.0.0.1", id="target-input")
                yield Static("Ports (comma-separated):")
                yield Input(value="80,443,8080,9090,6379", id="ports-input")
                yield Static("Spray Password (optional):")
                yield Input(placeholder="e.g. admin", id="spray-input")
                yield Checkbox("Enable Fuzzing (--fuzz)", id="fuzz-check")
                yield Checkbox("Enable Audit (--audit)", id="audit-check", value=True)
                yield Button("🚀 Launch Scan & Audit", id="launch-btn")
            with Vertical(id="main-content"):
                yield Static("[bold cyan]📊 Discovered Services & Findings[/bold cyan]")
                yield DataTable(id="results-table")
                yield Static("[bold cyan]📋 Live Execution Logs & CVE Advisories[/bold cyan]")
                yield RichLog(id="log-view", highlight=True, markup=True)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#results-table", DataTable)
        table.add_columns("Host", "Port", "Status", "Audit / Findings")
        log = self.query_one("#log-view", RichLog)
        log.write("[green][*] TermAnalyzer TUI successfully loaded. Configure target and click Launch.[/green]")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "launch-btn":
            target = self.query_one("#target-input", Input).value.strip()
            ports_str = self.query_one("#ports-input", Input).value.strip()
            spray_pass = self.query_one("#spray-input", Input).value.strip() or None
            fuzz = self.query_one("#fuzz-check", Checkbox).value
            audit = self.query_one("#audit-check", Checkbox).value

            log = self.query_one("#log-view", RichLog)
            table = self.query_one("#results-table", DataTable)
            table.clear()

            log.write(f"[bold yellow][*] Starting async reconnaissance on target: {target}[/bold yellow]")

            try:
                ports = [int(p.strip()) for p in ports_str.split(",")]
                tester = PortTester(target=target)

                if target.lower() == "local":
                    interfaces = discover_local_interfaces()
                    non_loopback = [ip for ip in interfaces if not ip.startswith("127.")]
                    if non_loopback:
                        base_ip = non_loopback[0]
                        parts = base_ip.split(".")
                        target = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                    else:
                        target = "127.0.0.1"
                    log.write(f"[*] Auto-resolved local subnet to: {target}")
                    tester = PortTester(target=target)

                if "/" in target:
                    open_services = await tester.scan_subnet(target, ports)
                else:
                    open_services = await tester.scan_ports(ports)

                if not open_services:
                    log.write("[red][-] No open services found on target scope.[/red]")
                    return

                audit_findings = []
                for svc in open_services:
                    finding = "Secure / N/A"
                    if audit:
                        audit_res = await PortTester(target=svc.host).audit_service(svc.port, svc.banner)
                        if audit_res["vulnerable"]:
                            finding = audit_res["details"]
                            audit_findings.append(f"HIGH: [{svc.host}:{svc.port}] {finding}")

                    table.add_row(str(svc.host), str(svc.port), svc.status, finding)
                    log.write(f"[green][+] Discovered: {svc.host}:{svc.port} ({svc.status}) -> {finding}[/green]")

                    # Handle Spraying if specified
                    web_ports = {80, 443, 8080, 8443, 8000, 5000, 9090}
                    if spray_pass and (svc.port in web_ports or "http" in svc.banner.lower()):
                        scheme = "https" if svc.port in {443, 8443} else "http"
                        base_url = f"{scheme}://{svc.host}:{svc.port}"
                        log.write(f"[*] Spraying password '{spray_pass}' against {base_url}...")
                        usernames = ["admin", "root", "user", "guest", "administrator", "postgres", "tomcat"]
                        hits = await tester.credential_spray_http(base_url, usernames, spray_pass)
                        for hit in hits:
                            log.write(f"[bold red][!] SPRAY SUCCESS: {hit['username']}:{hit['password']} at {base_url}[/bold red]")
                            table.add_row(str(svc.host), str(svc.port), "HIT", f"Spray Success: {hit['username']}")

                # Rule engine evaluation
                engine = RuleEngine()
                log_lines = [f"info: Discovered open port {s.port} banner: {s.banner}" for s in open_services]
                for af in audit_findings:
                    log_lines.append(f"critical: {af}")

                matches = engine.evaluate(log_lines)
                for m in matches:
                    log.write(f"[bold red]🚨 CVE ADVISORY [{m.get('severity').upper()} - CVSS {m.get('cvss')}]: {m.get('rule_id')} - {m.get('description')}[/bold red]")

                log.write("[green][+] Reconnaissance and audit execution completed successfully![/green]")

            except Exception as e:
                log.write(f"[bold red][-] Error during execution: {str(e)}[/bold red]")
