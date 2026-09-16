import asyncio
import aiohttp
import random
from rich.console import Console

console = Console()

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0"
]

def load_payload_files(paths_str):
    """Loads multiple payload files separated by commas."""
    file_paths = [p.strip() for p in paths_str.split(",")]
    all_payloads = []
    for fp in file_paths:
        with open(fp, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
            all_payloads.append(lines)
    return all_payloads

def build_multimarker_request(template, payload_tuple):
    """Replaces each successive '§§' in the template with items from payload_tuple."""
    if not template:
        return None
    parts = template.split("§§")
    result = []
    for i, part in enumerate(parts[:-1]):
        result.append(part)
        p_val = payload_tuple[min(i, len(payload_tuple) - 1)]
        result.append(str(p_val))
    result.append(parts[-1])
    return "".join(result)

async def fuzz_advanced(session, method, url_template, body_template, payload_tuple, semaphore, delay=0.0, base_headers=None, rotate_ua=False, smart_pause=False, lockout_str=None, pause_duration=15.0, pause_lock=None, extract_patterns=None, proxy=None):
    async with semaphore:
        if delay > 0:
            await asyncio.sleep(delay)
            
        target_url = build_multimarker_request(url_template, payload_tuple)
        body = build_multimarker_request(body_template, payload_tuple) if body_template else None
        
        headers = dict(base_headers) if base_headers else {}
        if rotate_ua:
            headers["User-Agent"] = random.choice(USER_AGENTS)
            
        request_kwargs = {"headers": headers, "ssl": False}
        if proxy:
            request_kwargs["proxy"] = proxy
            
        if body is not None:
            request_kwargs["data"] = body

        try:
            async with session.request(method.upper(), target_url, **request_kwargs) as response:
                text = await response.text()
                
                is_rate_limited = (response.status == 429) or (lockout_str and lockout_str in text)
                if smart_pause and is_rate_limited:
                    async with pause_lock:
                        console.print(f"\n[bold yellow][!] Rate-limit detected (Status: {response.status}). Pausing execution for {pause_duration}s...[/bold yellow]")
                        await asyncio.sleep(pause_duration)

                from term_analyzer.rules import extract_secrets
                secrets = extract_secrets(text, extract_patterns) if extract_patterns else {}
                return (payload_tuple, response.status, len(text), text, secrets)
        except Exception as e:
            return (payload_tuple, 0, 0, str(e), {})

def get_defaults_for_port(port):
    return {}

def test_http_auth(url, user, password, **kwargs):
    return False

def run_credential_spray(targets, users, passwords, **kwargs):
    pass
