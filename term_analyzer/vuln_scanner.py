import asyncio
import aiohttp
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console

console = Console()

XSS_PAYLOAD = "<script>alert('term_analyzer_xss')</script>"
SQLI_PAYLOAD = "' OR '1'='1"

async def test_endpoint_vulnerabilities(session, url, method="GET", form_inputs=None):
    """Actively tests a URL or form input fields for common vulnerabilities."""
    findings = []
    
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    
    # 1. Test Query Parameters for SQLi & XSS
    if query_params:
        for param in query_params:
            # Test XSS
            test_params = query_params.copy()
            test_params[param] = [XSS_PAYLOAD]
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            
            try:
                async with session.get(test_url, timeout=5) as resp:
                    text = await resp.text()
                    if XSS_PAYLOAD in text:
                        findings.append({
                            "type": "Reflected Cross-Site Scripting (XSS)",
                            "parameter": param,
                            "vector": test_url,
                            "severity": "High"
                        })
            except Exception:
                pass

            # Test SQLi Error/Content-based
            test_params[param] = [SQLI_PAYLOAD]
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            
            try:
                async with session.get(test_url, timeout=5) as resp:
                    text = await resp.text()
                    if "syntax" in text.lower() or "sqlite3" in text.lower() or "mysql" in text.lower() or "flag{" in text.lower():
                        findings.append({
                            "type": "SQL Injection (Error/Content-based)",
                            "parameter": param,
                            "vector": test_url,
                            "severity": "Critical"
                        })
            except Exception:
                pass

    # 2. Test Form Inputs if provided
    if form_inputs and method.upper() == "POST":
        for field in form_inputs:
            form_data = {field: XSS_PAYLOAD}
            try:
                async with session.post(url, data=form_data, timeout=5) as resp:
                    text = await resp.text()
                    if XSS_PAYLOAD in text:
                        findings.append({
                            "type": "Form-based Reflected XSS",
                            "parameter": field,
                            "vector": f"POST {url} with {field}={XSS_PAYLOAD}",
                            "severity": "High"
                        })
            except Exception:
                pass

    return findings

async def run_vulnerability_scan(endpoints, forms, concurrency=10):
    """Runs automated vulnerability checks across all discovered endpoints and forms."""
    console.print(f"[bold cyan][*] Running automated vulnerability checks on {len(endpoints)} pages and {len(forms)} forms...[/bold cyan]")
    
    semaphore = asyncio.Semaphore(concurrency)
    all_findings = []

    async with aiohttp.ClientSession() as session:
        for ep in endpoints:
            async with semaphore:
                vulns = await test_endpoint_vulnerabilities(session, ep["url"])
                for v in vulns:
                    console.print(f"[bold red][VULN FOUND] [{v['severity'].upper()}] {v['type']} in param '{v['parameter']}' -> {v['vector']}[/bold red]")
                    all_findings.append(v)
                    
        for form in forms:
            async with semaphore:
                vulns = await test_endpoint_vulnerabilities(session, form["action"], method=form["method"], form_inputs=form["inputs"])
                for v in vulns:
                    console.print(f"[bold red][VULN FOUND] [{v['severity'].upper()}] {v['type']} -> {v['vector']}[/bold red]")
                    all_findings.append(v)

    console.print(f"[bold green][+] Vulnerability scan complete. Identified {len(all_findings)} potential security flaw(s).[/bold green]")
    return all_findings
