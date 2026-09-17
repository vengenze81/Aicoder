import asyncio
import argparse
import sys
from core.plugin_manager import PluginManager
from reporter import ScanReporter

async def main():
    plugin_manager = PluginManager()
    plugins = plugin_manager.discover_plugins()

    parser = argparse.ArgumentParser(description="Modular Async Security Reconnaissance & Offensive Framework (Plugin-Driven)")
    parser.add_argument("target", help="Target URL (e.g., https://medistore.se)")
    
    # Dynamically register arguments based on discovered plugins
    for p_id, p_info in plugins.items():
        meta = p_info["meta"]
        parser.add_argument(meta["flag"], action="store_true", help=meta["description"])
    
    parser.add_argument("--all", action="store_true", help="Run all discovered plugins sequentially")

    args = parser.parse_args()
    target_url = args.target
    reporter = ScanReporter(target_url)

    print(f"[*] Initializing plugin-driven framework against: {target_url}")
    print(f"[*] Loaded active plugins: {list(plugins.keys())}")

    executed = False
    for p_id, p_info in plugins.items():
        meta = p_info["meta"]
        flag_attr = meta["flag"].lstrip("-").replace("-", "_")
        
        if args.all or getattr(args, flag_attr, False):
            print(f"\n[*] Executing Plugin: {meta['name']}...")
            await p_info["run"](target_url, reporter=reporter)
            executed = True

    if not executed and not args.all:
        print("\n[!] No module flags specified. Use --help to view available plugin options.")

    # Save reports
    reporter.save_markdown()
    reporter.save_json()
    reporter.save_html()
    print(f"\n[+] Audit completed. Reports saved to scan_report.md, scan_report.json, and scan_report.html")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 main.py <TARGET_URL> [MODULE_FLAGS]")
        sys.argv.append("--help")
    asyncio.run(main())
