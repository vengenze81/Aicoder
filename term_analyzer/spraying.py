import asyncio
import aiohttp
import random
from rich.console import Console
from term_analyzer.secrets_finder import extract_secrets

console = Console()

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
]

def load_payload_files(filepaths_str):
    """Loads one or more comma-separated payload files."""
    paths = [p.strip() for p in filepaths_str.split(",")]
    all_payload_lists = []
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                all_payload_lists.append(payloads)
        except Exception as e:
            console.print(f"[bold red][!] Error loading payload file {path}: {e}[/bold red]")
            all_payload_lists.append([])
    return all_payload_lists

async def fuzz_advanced(session, method, url_template, body_template, payload_tuple, semaphore, delay=0.0, rotate_ua=False, smart_pause=False, lockout_str=None, pause_duration=15.0, pause_lock=None, custom_headers=None, custom_cookies=None):
    url = url_template
    for i, payload in enumerate(payload_tuple):
        url = url.replace(f"§§", str(payload), 1)
        
    body = body_template
    if body:
        for i, payload in enumerate(payload_tuple):
            body = body.replace(f"§§", str(payload), 1)

    headers = dict(custom_headers) if custom_headers else {}
    if rotate_ua:
        headers["User-Agent"] = random.choice(USER_AGENTS)

    async with semaphore:
        if delay > 0:
            await asyncio.sleep(delay)
            
        if pause_lock and pause_lock.locked():
            async with pause_lock:
                pass

        try:
            async with session.request(method.upper(), url, data=body, headers=headers, cookies=custom_cookies, allow_redirects=False, timeout=10) as response:
                status = response.status
                text = await response.text()
                length = len(text)
                secrets = extract_secrets(text)
                
                if smart_pause and status == 429:
                    if pause_lock and not pause_lock.locked():
                        async with pause_lock:
                            console.print(f"[bold yellow][!] Rate limit (429) encountered. Pausing all tasks for {pause_duration}s...[/bold yellow]")
                            await asyncio.sleep(pause_duration)
                            
                if lockout_str and lockout_str in text:
                    if pause_lock and not pause_lock.locked():
                        async with pause_lock:
                            console.print(f"[bold red][!] Lockout string detected! Pausing tasks for {pause_duration}s...[/bold red]")
                            await asyncio.sleep(pause_duration)
                            
                return payload_tuple, status, length, text, secrets
        except Exception as e:
            return payload_tuple, 0, 0, str(e), []
