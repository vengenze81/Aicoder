import asyncio
import sys
import io
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Button, Input, RichLog, Static
from textual.containers import Container, Horizontal, Vertical

from core.plugin_manager import PluginManager
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
        self.plugin_manager = PluginManager()
        self.plugins = self.plugin_manager.discover_plugins()
        self.current_task = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="top-bar"):
            yield Static("[bold]Target Base URL:[/bold]")
            yield Input(value="https://medistore.se", id="target-input")
        with Horizontal(id="main-content"):
            with Vertical(id="sidebar"):
                yield Static("[bold red]Dynamic Plugin Registry[/bold red]\n")
                
                # Dynamically generate buttons for each loaded plugin
                for p_id, p_info in self.plugins.items():
                    meta = p_info["meta"]
                    variant = "error" if meta.get("category") == "offensive" else "primary"
                    yield Button(meta["name"], id=f"plugin-{p_id}", variant=variant)
                
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

        if button_id.startswith("plugin-"):
            plugin_id = button_id.replace("plugin-", "")
            if plugin_id in self.plugins:
                self.current_task = asyncio.create_task(self.run_plugin_task(plugin_id, target_url, log))

    async def run_plugin_task(self, plugin_id, target_url, log):
        plugin = self.plugins[plugin_id]
        meta = plugin["meta"]
        reporter = ScanReporter(target_url)
        old_stdout = sys.stdout
        sys.stdout = StreamToLog(log)

        log.write(f"[bold cyan]>>> Executing Plugin [{meta['name']}]: {target_url}[/bold cyan]")

        try:
            await plugin["run"](target_url, reporter=reporter)
            reporter.save_markdown()
            reporter.save_json()
            reporter.save_html()
            log.write(f"[bold green]<<< Plugin '{meta['name']}' finished. Reports updated.[/bold green]")
        except asyncio.CancelledError:
            log.write("[bold red][-] Task cancelled gracefully.[/bold red]")
        except Exception as e:
            log.write(f"[bold red][-] Execution error: {e}[/bold red]")
        finally:
            sys.stdout = old_stdout

if __name__ == "__main__":
    app = SecurityDashboard()
    app.run()
