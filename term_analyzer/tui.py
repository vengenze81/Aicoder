import asyncio
import sys
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from term_analyzer.db import DatabaseManager
from term_analyzer.tester import PortTester

console = Console()

async def interactive_tui():
    # Local import to prevent circular dependency with cli.py
    from term_analyzer.cli import run_scan_on_target, load_config

    db = DatabaseManager()
    while True:
        console.clear()
        console.print(Panel.fit("[bold cyan]Term-Analyzer TUI Dashboard[/bold cyan]\n[dim]Advanced Asynchronous Reconnaissance & Fuzzing Suite[/dim]", border_style="cyan"))
        
        console.print("[1] [green]Run Single Target Scan (--scan)[/green]")
        console.print("[2] [green]Run CIDR Subnet Sweep (--cidr)[/green]")
        console.print("[3] [yellow]View Scan History (SQLite Archive)[/yellow]")
        console.print("[4] [blue]View Current Configuration (config.json)[/blue]")
        console.print("[5] [red]Exit[/red]\n")
        
        choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4", "5"], default="1")
        config = load_config()
        
        if choice == "1":
            target = Prompt.ask("Enter target IP or hostname")
            if target:
                console.print(f"[cyan]Launching scan on {target}...[/cyan]")
                await run_scan_on_target(
                    target=target,
                    ports_str=config.get("ports", "21,22,80,443,3306,8080"),
                    fuzz=True,
                    audit=config.get("audit", True),
                    output=config.get("output", "recon_report.html"),
                    ext=config.get("ext", ""),
                    recursive=config.get("recursive", False),
                    wordlist=config.get("wordlist", "")
                )
                Prompt.ask("\n[bold green]Scan complete! Press Enter to return to menu...[/bold green]")
        
        elif choice == "2":
            cidr = Prompt.ask("Enter CIDR subnet (e.g. 192.168.68.0/24)")
            if cidr:
                console.print(f"[cyan]Sweeping CIDR block {cidr} for live hosts...[/cyan]")
                dummy_tester = PortTester("127.0.0.1")
                live_hosts = await dummy_tester.discover_live_hosts(cidr)
                if not live_hosts:
                    console.print(f"[red]No live hosts discovered on {cidr}.[/red]")
                else:
                    console.print(f"[green]Discovered live hosts: {live_hosts}[/green]")
                    for target in live_hosts:
                        await run_scan_on_target(
                            target=target,
                            ports_str=config.get("ports", "21,22,80,443,3306,8080"),
                            fuzz=True,
                            audit=config.get("audit", True),
                            output=config.get("output", "recon_report.html"),
                            ext=config.get("ext", ""),
                            recursive=config.get("recursive", False),
                            wordlist=config.get("wordlist", "")
                        )
                Prompt.ask("\n[bold green]CIDR sweep complete! Press Enter to return to menu...[/bold green]")
        
        elif choice == "3":
            console.print("[bold yellow]Recent Scan History (SQLite Archive):[/bold yellow]")
            scans = db.get_all_scans()
            if not scans:
                console.print("[dim]No historical scans found in database yet.[/dim]")
            else:
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("ID", style="dim", width=6)
                table.add_column("Target", style="cyan")
                table.add_column("Timestamp", style="green")
                
                for s in scans:
                    table.add_row(str(s["id"]), s["target"], s["timestamp"])
                console.print(table)
            Prompt.ask("\n[bold green]Press Enter to return to menu...[/bold green]")
        
        elif choice == "4":
            console.print("[bold blue]Current Configuration (config.json):[/bold blue]")
            for k, v in config.items():
                console.print(f"  [cyan]{k}:[/cyan] [white]{v}[/white]")
            Prompt.ask("\n[bold green]Press Enter to return to menu...[/bold green]")
        
        elif choice == "5":
            console.print("[cyan]Exiting Term-Analyzer TUI. Stay secure![/cyan]")
            sys.exit(0)
