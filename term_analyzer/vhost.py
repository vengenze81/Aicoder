import asyncio
import aiohttp
from aiohttp_socks import ProxyConnector
from rich.console import Console

console = Console()

async def fuzz_vhost_single(session, target_url, base_domain, subdomain, semaphore):
    vhost = f"{subdomain}.{base_domain}" if subdomain else base_domain
    headers = {"Host": vhost}
    async with semaphore:
        try:
            async with session.get(target_url, headers=headers, allow_redirects=False, timeout=10) as response:
                status = response.status
                text = await response.text()
                length = len(text)
                return vhost, status, length, text[:150], None
        except Exception as e:
            return vhost, 0, 0, str(e), None

async def run_vhost_scan(target_url, base_domain, wordlist_path, concurrency=10, proxy=None, exclude_statuses=None, exclude_lengths=None):
    exclude_statuses = exclude_statuses or set()
    exclude_lengths = exclude_lengths or set()
    
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            subdomains = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except Exception as e:
        console.print(f"[bold red][!] Error loading wordlist {wordlist_path}: {e}[/bold red]")
        return []

    console.print(f"[bold cyan][*] Loaded {len(subdomains)} subdomains for VHost fuzzing against {target_url} (Domain: {base_domain})[/bold cyan]")
    
    connector = ProxyConnector.from_url(proxy) if proxy else None
    semaphore = asyncio.Semaphore(concurrency)
    
    results = []
    filtered_count = 0
    
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            fuzz_vhost_single(session, target_url, base_domain, sub, semaphore)
            for sub in subdomains
        ]
        responses = await asyncio.gather(*tasks)
        
    for vhost, status, length, text, err in responses:
        if status in exclude_statuses or length in exclude_lengths:
            filtered_count += 1
            continue
            
        results.append({
            "payloads": [vhost],
            "status_code": status,
            "response_length": length,
            "response_snippet": text
        })
        
        console.print(f"[bold green][+] VHost Hit: [cyan]{vhost}[/cyan] -> Status: {status} | Length: {length}[/bold green]")
        
    if filtered_count > 0:
        console.print(f"[dim][*] Filtered out {filtered_count} uninteresting VHost response(s).[/dim]")
        
    return results
