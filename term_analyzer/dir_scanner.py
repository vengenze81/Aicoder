import asyncio
import aiohttp
from aiohttp_socks import ProxyConnector
from rich.console import Console
from urllib.parse import urljoin
from term_analyzer.secrets_finder import extract_secrets

console = Console()

async def fuzz_path_single(session, target_url, path, semaphore, custom_headers, custom_cookies):
    clean_path = path.lstrip('/')
    url = urljoin(target_url if target_url.endswith('/') else target_url + '/', clean_path)
    async with semaphore:
        try:
            async with session.get(url, headers=custom_headers, cookies=custom_cookies, allow_redirects=False, timeout=10) as response:
                status = response.status
                text = await response.text()
                length = len(text)
                secrets = extract_secrets(text)
                return path, url, status, length, text[:150], secrets, None
        except Exception as e:
            return path, url, 0, 0, str(e), [], None

async def run_dir_scan(target_url, wordlist_path, concurrency=20, proxy=None, exclude_statuses=None, exclude_lengths=None, custom_headers=None, custom_cookies=None):
    exclude_statuses = exclude_statuses or set()
    exclude_lengths = exclude_lengths or set()
    
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            paths = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except Exception as e:
        console.print(f"[bold red][!] Error loading wordlist {wordlist_path}: {e}[/bold red]")
        return []

    console.print(f"[bold cyan][*] Loaded {len(paths)} paths for directory brute-forcing against {target_url}[/bold cyan]")
    
    connector = ProxyConnector.from_url(proxy) if proxy else None
    semaphore = asyncio.Semaphore(concurrency)
    
    results = []
    filtered_count = 0
    
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            fuzz_path_single(session, target_url, path, semaphore, custom_headers, custom_cookies)
            for path in paths
        ]
        responses = await asyncio.gather(*tasks)
        
    for path, url, status, length, text, secrets, err in responses:
        if status in exclude_statuses or length in exclude_lengths:
            filtered_count += 1
            continue
            
        results.append({
            "payloads": [url],
            "status_code": status,
            "response_length": length,
            "response_snippet": text,
            "extracted_secrets": secrets
        })
        
        color = "green" if status == 200 else ("yellow" if status in [301, 302, 403] else "dim")
        console.print(f"[{color}][+] Found: [cyan]{url}[/cyan] -> Status: {status} | Length: {length}[/{color}]")
        if secrets:
            for s in secrets:
                console.print(f"    [bold red]⚠️ SENSITIVE DATA LEAK: {s['secret_type']} -> {s['matches']}[/bold red]")
        
    if filtered_count > 0:
        console.print(f"[dim][*] Filtered out {filtered_count} uninteresting response(s).[/dim]")
        
    return results
