import os
import zipfile
import re
from rich.console import Console

console = Console()

SECRET_PATTERNS = {
    "API Key": r"(?i)(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,45})['\"]",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "JWT Token": r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
    "Generic Secret": r"(?i)(password|secret|token)['\"]?\s*[:=]\s*['\"]([^\'\"]{8,})['\"]"
}

def audit_apk(apk_path):
    """Performs static security analysis on an Android APK file."""
    console.print(f"[bold cyan][*] Starting static audit of APK: {apk_path}...[/bold cyan]")
    findings = []
    
    if not os.path.exists(apk_path):
        console.print(f"[bold red][!] APK file not found: {apk_path}[/bold red]")
        return findings

    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            file_list = zf.namelist()
            console.print(f"[green][+] Successfully opened APK. Total files inside: {len(file_list)}[/green]")
            
            # 1. Check AndroidManifest.xml
            if "AndroidManifest.xml" in file_list:
                manifest_bytes = zf.read("AndroidManifest.xml")
                manifest_str = ""
                try:
                    manifest_str = manifest_bytes.decode('utf-8', errors='ignore')
                except Exception:
                    pass
                try:
                    manifest_str += " " + manifest_bytes.decode('utf-16le', errors='ignore')
                except Exception:
                    pass

                # Check manifest configurations
                if "allowBackup" in manifest_str or b'allowBackup' in manifest_bytes:
                    findings.append({
                        "type": "Android Manifest Misconfiguration",
                        "details": "allowBackup is enabled (allows local data extraction via adb backup).",
                        "severity": "Medium"
                    })
                    console.print("[yellow][!] [MEDIUM] Manifest: allowBackup is enabled.[/yellow]")

                if "debuggable" in manifest_str or b'debuggable' in manifest_bytes:
                    findings.append({
                        "type": "Android Manifest Misconfiguration",
                        "details": "Application is marked debuggable (allows code injection and debugging in production).",
                        "severity": "Critical"
                    })
                    console.print("[bold red][VULN FOUND] [CRITICAL] Manifest: Application is marked debuggable![/bold red]")

                if "usesCleartextTraffic" in manifest_str or b'usesCleartextTraffic' in manifest_bytes:
                    findings.append({
                        "type": "Android Manifest Misconfiguration",
                        "details": "Cleartext HTTP traffic is permitted.",
                        "severity": "Low"
                    })
                    console.print("[yellow][!] [LOW] Manifest: Cleartext traffic is enabled.[/yellow]")
            else:
                console.print("[yellow][!] AndroidManifest.xml not found directly in root.[/yellow]")

            # 2. Scan internal text/xml/json files for hardcoded secrets
            console.print("[cyan][*] Scanning APK contents for hardcoded secrets and endpoints...[/cyan]")
            scanned_files = 0
            for filename in file_list:
                if filename.endswith(('.xml', '.json', '.txt', '.properties', '.html', '.js')):
                    try:
                        content = zf.read(filename).decode('utf-8', errors='ignore')
                        scanned_files += 1
                        for sec_name, pattern in SECRET_PATTERNS.items():
                            matches = re.findall(pattern, content)
                            if matches:
                                findings.append({
                                     "type": f"Hardcoded {sec_name}",
                                     "details": f"Found in file: {filename}",
                                     "severity": "High"
                                })
                                console.print(f"[bold red][VULN FOUND] [HIGH] Hardcoded {sec_name} in {filename}[/bold red]")
                    except Exception:
                        continue
            console.print(f"[green][+] Scanned {scanned_files} configuration/text files for secrets.[/green]")

    except Exception as e:
        console.print(f"[bold red][!] Error processing APK file: {e}[/bold red]")

    console.print(f"[bold green][+] APK static audit complete. Found {len(findings)} issue(s).[/bold green]")
    return findings
