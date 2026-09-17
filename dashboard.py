import asyncio
import sys
import io
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Button, Input, RichLog, Static
from textual.containers import Container, Horizontal, Vertical

# Import your core framework modules
from vuln_scanner import scan_wordpress_plugins
from file_scanner import scan_sensitive_files
from xmlrpc_tester import test_xmlrpc
from header_scanner import scan_security_headers
from waf_profiler import profile_waf
from reporter import ScanReporter

class StreamToLog(io.TextIOBase):
    """Custom stdout redirector to push print statements directly into the Textual RichLog widget."""
    def __init__(self, log_widget):
        self.log_widget = log_widget

    def write(self, text):
        if text.strip():
            self.log_widget.write(text.rstrip())
        return len(text)

class SecurityDashboard(App):
    """Interactive TUI Dashboard for the Modular Security Framework"""
    
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
        width: 32;
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

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="top-bar"):
            yield Static("[bold]Target Base URL:[/bold]")
            yield Input(value="https://medistore.se", id="target-input")
        with Horizontal(id="main-content"):
            with Vertical(id="sidebar"):
                yield Static("[bold cyan]Audit Modules[/bold cyan]\n")
                yield Button("1. Plugin Vuln Scan", id="btn-vuln", variant="primary")
                yield Button("2. Sensitive Files", id="btn-file", variant="primary")
                yield Button("3. XML-RPC Probe", id="btn-xmlrpc", variant="primary")
                yield Button("4. Header Audit", id="btn-header", variant="primary")
                yield Button("5. WAF Profiler", id="btn-waf", variant="primary")
            yield RichLog(id="log-view", highlight=True, markup=True)
        yield Footer()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        target_input = self.query_one("#target-input", Input)
        target_url = target_input.value.strip()
        log = self.query_one("#log-view", RichLog)
        
        reporter = ScanReporter(target_url)
        
        # Redirect standard output to stream prints directly into the TUI log view
        old_stdout = sys.stdout
        sys.stdout = StreamToLog(log)

        log.write(f"[bold cyan]>>> Initializing task against target: {target_url}[/bold cyan]")

        try:
            if button_id == "btn-vuln":
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
            
            reporter.save_markdown()
            log.write("[bold green]<<< Module execution finished. Report saved to scan_report.md[/bold green]")
        except Exception as e:
            log.write(f"[bold red][-] Execution error: {e}[/bold red]")
        finally:
            sys.stdout = old_stdout

if __name__ == "__main__":
    app = SecurityDashboard()
    app.run()
