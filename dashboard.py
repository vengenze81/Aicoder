import asyncio
import sys
import io
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Button, Input, RichLog, Static
from textual.containers import Container, Horizontal, Vertical

# Import all core framework modules including Directory Brute-Forcer
from vuln_scanner import scan_wordpress_plugins
from file_scanner import scan_sensitive_files
from xmlrpc_tester import test_xmlrpc
from header_scanner import scan_security_headers
from waf_profiler import profile_waf
from auth_tester import run_credential_audit
from js_extractor import extract_javascript_assets
from subdomain_enum import enumerate_subdomains
from port_scanner import scan_ports
from api_discover import discover_api_endpoints
from ssl_scanner import audit_ssl_certificate
from vuln_fuzzer import run_offensive_fuzz
from dir_brute import run_dir_brute
from reporter import ScanReporter

class StreamToLog(io.TextIOBase):
    def __init__(self, log_widget):
        self.log_widget = log_widget

    def write(self, text):
        if text.strip():
            self.log_widget.write(text.rstrip())
        return len(text)

class SecurityDashboard(App):
    CSS = """
    Screen {
        layout: vertical;
        background: $surface;
    }
    #top-bar {
        height: auto;
        dock: top;
        padding: 1 2;
        background: $boost;
    }
    #main-content {
        layout: horizontal;
        height: 1fr;
    }
    #sidebar {
        width: 38;
        dock: left;
        padding: 1;
        background: $panel;
        border-right: solid $primary;
    }
    #log-view {
        height: 1fr;
        border: solid $accent;
        margin: 1;
        background: #000000;
    }
    Button {
        width: 100%;
        margin-bottom: 1;
    }
    Input {
        margin-top: 1;
    }
    """

    def __init__(self):
        super().__init__()
        self.current_task = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="top-bar"):
            yield Static("[bold]Target Base URL:[/bold]")
            yield Input(value="https://medistore.se", id="target-input")
        with Horizontal(id="main-content"):
            with Vertical(id="sidebar"):
                yield Static("[bold red]Offensive Modules[/bold red]\n")
                yield Button("1. Offensive Vuln Fuzzer", id="btn-fuzz", variant="error")
                yield Button("2. Directory Brute-Force", id="btn-brute", variant="error")
                yield Static("\n[bold cyan]Recon Modules[/bold cyan]\n")
                yield Button("3. SSL/TLS Audit", id="btn-ssl", variant="primary")
                yield Button("4. API Discovery", id="btn-api", variant="primary")
                yield Button("5. Port Scanner", id="btn-port", variant="primary")
                yield Button("6. Subdomain Enum", id="btn-sub", variant="primary")
                yield Button("7. Plugin Vuln Scan", id="btn-vuln", variant="primary")
                yield Button("8. Sensitive Files", id="btn-file", variant="primary")
                yield Button("9. XML-RPC Probe", id="btn-xmlrpc", variant="primary")
                yield Button("10. Header Audit", id="btn-header", variant="primary")
                yield Button("11. WAF Profiler", id="btn-waf", variant="primary")
                yield Button("12. Credential Audit", id="btn-auth", variant="warning")
                yield Button("13. JS Extractor", id="btn-js", variant="primary")
                yield Static("\n")
                yield Button("🛑 Abort Current Scan", id="btn-cancel", variant="error")
            yield RichLog(id="log-view", highlight=True, markup=True)
        yield Footer()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        log = self.query_one("#log-view", RichLog)
        
        if button_id == "btn-cancel":
            if self.current_task and not self.current_task.done():
                self.current_task.cancel()
                log.write("[bold red][!] Active scan task aborted by user request.[/bold red]")
            else:
                log.write("[yellow][*] No active scan running to abort.[/yellow]")
            return

        if self.current_task and not self.current_task.done():
            log.write("[bold yellow][!] A scan is already in progress. Please click 'Abort Current Scan' first.[/bold yellow]")
            return

        target_input = self.query_one("#target-input", Input)
        target_url = target_input.value.strip()

        self.current_task = asyncio.create_task(self.run_module_task(button_id, target_url, log))

    async def run_module_task(self, button_id, target_url, log):
        reporter = ScanReporter(target_url)
        old_stdout = sys.stdout
        sys.stdout = StreamToLog(log)

        log.write(f"[bold cyan]>>> Initializing background task against target: {target_url}[/bold cyan]")

        try:
            if button_id == "btn-fuzz":
                log.write("[red]Executing Offensive Vulnerability Fuzzer (SQLi, LFI, XSS)...[/red]")
                await run_offensive_fuzz(target_url, reporter=reporter)
            elif button_id == "btn-brute":
                log.write("[red]Executing Async Directory & Content Brute-Forcer...[/red]")
                await run_dir_brute(target_url, reporter=reporter)
            elif button_id == "btn-ssl":
                log.write("[yellow]Executing SSL/TLS Certificate & Transport Auditor...[/yellow]")
                await audit_ssl_certificate(target_url, reporter=reporter)
            elif button_id == "btn-api":
                log.write("[yellow]Executing API Endpoint & Documentation Discovery...[/yellow]")
                await discover_api_endpoints(target_url, reporter=reporter)
            elif button_id == "btn-port":
                log.write("[yellow]Executing Async Port & Banner Scanner...[/yellow]")
                await scan_ports(target_url, reporter=reporter)
            elif button_id == "btn-sub":
                log.write("[yellow]Executing Subdomain Enumeration Module...[/yellow]")
                await enumerate_subdomains(target_url, reporter=reporter)
            elif button_id == "btn-vuln":
                log.write("[yellow]Executing WordPress Plugin Vulnerability Fingerprinter...[/yellow]")
                await scan_wordpress_plugins(target_url, reporter=reporter)
            elif button_id == "btn-file":
                log.write("[yellow]Executing Sensitive File & Backup Scanner...[/yellow]")
                await scan_sensitive_files(target_url, reporter=reporter)
            elif button_id == "btn-xmlrpc":
                log.write("[yellow]Executing XML-RPC Endpoint Probe...[/yellow]")
                await test_xmlrpc(target_url, reporter=reporter)
            elif button_id == "btn-header":
                log.write("[yellow]Executing HTTP Security Headers Audit...[/yellow]")
                await scan_security_headers(target_url, reporter=reporter)
            elif button_id == "btn-waf":
                log.write("[yellow]Executing WAF Rate-Limit Concurrency Profiler...[/yellow]")
                await profile_waf(target_url, reporter=reporter)
            elif button_id == "btn-auth":
                log.write("[yellow]Executing Credential Audit...[/yellow]")
                await run_credential_audit(target_url, "discovered_usernames.txt", "passwords.txt", timeout=8.0)
            elif button_id == "btn-js":
                log.write("[yellow]Executing JavaScript Asset & Secret Extractor...[/yellow]")
                await extract_javascript_assets(target_url, reporter=reporter)
            
            reporter.save_markdown()
            reporter.save_json()
            reporter.save_html()
            log.write("[bold green]<<< Module execution finished. Reports saved to Markdown, JSON, and HTML.[/bold green]")
        except asyncio.CancelledError:
            log.write("[bold red][-] Task cancelled gracefully.[/bold red]")
        except Exception as e:
            log.write(f"[bold red][-] Execution error: {e}[/bold red]")
        finally:
            sys.stdout = old_stdout

if __name__ == "__main__":
    app = SecurityDashboard()
    app.run()
