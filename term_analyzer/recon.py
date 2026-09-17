import asyncio
import aiohttp
import socket
import re
from rich.console import Console

console = Console()

async def fetch_crt_sh(session, domain):
    """Fetches subdomains from crt.sh certificate transparency logs."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()
    try:
        async with session.get(url, timeout=10) as response:
            if response.status == 200:
                data = await response.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if name and not name.startswith("*.") and domain in name:
                            subdomains.add(name)
    except Exception as e:
        console.print(f"[dim][!] crt.sh passive recon error: {e}[/dim]")
    return subdomains

async def resolve_subdomain(subdomain):
    """Resolves a subdomain to an IP address using non-blocking getaddrinfo."""
    loop = asyncio.get_running_loop()
    try:
        await loop.getaddrinfo(subdomain, None, proto=socket.IPPROTO_TCP)
        return subdomain
    except Exception:
        return None

async def probe_url(session, url):
    """Probes an HTTP/HTTPS URL to check if it's alive."""
    try:
        async with session.get(url, timeout=5, allow_redirects=True) as resp:
            text = await resp.text()
            title_match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE)
            title = title_match.group(1).strip() if title_match else "No Title"
            return {
                "url": str(resp.url),
                "status": resp.status,
                "length": len(text),
                "title": title
            }
    except Exception:
        return None

async def run_recon(domain, wordlist_path=None, concurrency=20, proxy=None):
    """Performs full recon: passive OSINT + active brute force + HTTP probing."""
    console.print(f"[bold cyan][*] Starting attack surface recon for domain: {domain}[/bold cyan]")
    all_subdomains = set()

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        # 1. Passive Recon via crt.sh
        console.print("[cyan][*] Querying Certificate Transparency logs (crt.sh)...[/cyan]")
        crt_subs = await fetch_crt_sh(session, domain)
        console.print(f"[green][+] Found {len(crt_subs)} subdomain(s) via passive OSINT.[/green]")
        all_subdomains.update(crt_subs)

        # 2. Active Brute Force
        subs_to_check = []
        if wordlist_path:
            try:
                with open(wordlist_path, 'r') as f:
                    subs_to_check = [line.strip().lower() for line in f if line.strip() and not line.startswith('#')]
            except Exception:
                pass
        
        if not subs_to_check:
            subs_to_check = [
                "www", "api", "admin", "test", "dev", "staging", "app", 
                "mail", "login", "auth", "portal", "dashboard", "blog", 
                "shop", "secure", "vpn", "support", "status", "api-v1", "internal",
                "jenkins", "git", "metrics", "grafana", "kibana", "qa", "uat"
            ]

        candidate_subdomains = {f"{sub}.{domain}" for sub in subs_to_check}
        console.print(f"[cyan][*] Brute-forcing {len(candidate_subdomains)} candidate subdomains via DNS...[/cyan]")

        semaphore = asyncio.Semaphore(concurrency)
        async def bound_resolve(sub):
            async with semaphore:
                return await resolve_subdomain(sub)

        resolve_tasks = [bound_resolve(sub) for sub in candidate_subdomains]
        resolved_results = await asyncio.gather(*resolve_tasks)
        active_resolved = {res for res in resolved_results if res is not None}
        console.print(f"[green][+] DNS resolution confirmed {len(active_resolved)} active subdomain(s).[/green]")
        all_subdomains.update(active_resolved)

        # 3. HTTP Probing of all discovered unique subdomains
        console.print(f"[cyan][*] Probing HTTP/HTTPS services across {len(all_subdomains)} discovered subdomains...[/cyan]")
        urls_to_probe = []
        for sub in all_subdomains:
            urls_to_probe.append(f"http://{sub}")
            urls_to_probe.append(f"https://{sub}")

        async def bound_probe(url):
            async with semaphore:
                return await probe_url(session, url)

        probe_tasks = [bound_probe(u) for u in urls_to_probe]
        probe_results = await asyncio.gather(*probe_tasks)
        live_targets = [res for res in probe_results if res is not None]

        console.print(f"[bold green][+] Recon complete. Found {len(live_targets)} live web endpoint(s).[/bold green]")
        for target in live_targets:
            console.print(f"  [green]➔ [{target['status']}] {target['url']} ({target['title']})[/green]")

        formatted_results = []
        for t in live_targets:
            formatted_results.append({
                "payloads": [t["url"]],
                "status_code": t["status"],
                "response_length": t["length"],
                "response_snippet": f"Title: {t['title']}",
                "extracted_secrets": []
            })

        return formatted_results
