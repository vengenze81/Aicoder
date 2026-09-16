import asyncio
import aiohttp
from rich.console import Console

console = Console()

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy"
]

async def audit_headers_and_cors(target_url):
    """Audits response security headers and tests for dangerous CORS misconfigurations."""
    console.print(f"[bold cyan][*] Auditing security headers and CORS policies for {target_url}...[/bold cyan]")
    findings = []
    
    async with aiohttp.ClientSession() as session:
        # 1. Check Missing Security Headers
        try:
            async with session.get(target_url, timeout=5) as resp:
                headers = resp.headers
                missing_headers = [h for h in SECURITY_HEADERS if h not in headers]
                
                if missing_headers:
                    findings.append({
                        "type": "Missing Security Headers",
                        "details": f"Missing headers: {', '.join(missing_headers)}",
                        "severity": "Low"
                    })
                    console.print(f"[yellow][!] Missing Security Headers: {', '.join(missing_headers)}[/yellow]")
                else:
                    console.print("[green][+] All core security headers present.[/green]")
        except Exception as e:
            console.print(f"[bold red][!] Error connecting to target: {e}[/bold red]")
            return findings

        # 2. Check CORS Misconfigurations
        cors_test_origin = "https://evil-attacker.com"
        custom_headers = {"Origin": cors_test_origin}
        try:
            async with session.get(target_url, headers=custom_headers, timeout=5) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
                
                if acao == cors_test_origin or (acao == "*" and acac == "true"):
                    severity = "Critical" if acac == "true" else "Medium"
                    findings.append({
                        "type": "CORS Misconfiguration",
                        "details": f"Reflects arbitrary origin ('{acao}') with credentials allowed: {acac}",
                        "severity": severity
                    })
                    console.print(f"[bold red][VULN FOUND] [{severity.upper()}] CORS Misconfiguration: Arbitrary origin reflection detected ({acao})![/bold red]")
                else:
                    console.print("[green][+] No dangerous CORS reflection detected.[/green]")
        except Exception:
            pass

    console.print(f"[bold green][+] Headers and CORS audit complete. Found {len(findings)} issue(s).[/bold green]")
    return findings
