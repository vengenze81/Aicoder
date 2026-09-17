import asyncio
import httpx
import random
import re
import itertools
from config import USER_AGENTS, WAF_SIGNATURES, PROXY_LIST
from patterns import PATTERNS
from headers import analyze_security_headers

async def analyze_content(url, text, headers):
    findings = []
    combined_data = text + " " + str(headers)
    for label, pattern in PATTERNS.items():
        matches = re.findall(pattern, combined_data)
        if matches:
            findings.append((label, matches))
    return findings

async def stealth_probe(client, base_url, endpoint, proxy=None, max_retries=3):
    url = base_url.rstrip("/") + endpoint
    base_delay = 1.5

    for attempt in range(max_retries):
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive"
        }
        
        try:
            kwargs = {"headers": headers, "timeout": 8.0, "follow_redirects": True}
            if proxy:
                kwargs["proxy"] = proxy

            response = await client.get(url, **kwargs)
            body_lower = response.text.lower()

            is_blocked = (
                response.status_code in [429, 503] or 
                (response.status_code == 403 and any(sig in body_lower for sig in WAF_SIGNATURES))
            )

            if is_blocked:
                jitter = random.uniform(0.5, 2.0)
                sleep_time = (base_delay * (2 ** attempt)) + jitter
                print(f"[!] [WAF/Rate-Limit] Blocked on {url} (Proxy: {proxy or 'Direct'}). Backing off for {sleep_time:.2f}s...")
                await asyncio.sleep(sleep_time)
                continue

            if response.status_code not in [404, 410]:
                route_type = f"Proxy: {proxy}" if proxy else "Direct"
                print(f"[+] [HTTP {response.status_code}] [{route_type}] Valid: {url} (Size: {len(response.content)})")
                
                # Run regex body/header pattern grepping
                findings = await analyze_content(url, response.text, response.headers)
                for label, match_data in findings:
                    print(f"    └── [MATCH FOUND] {label}: {match_data[:3]} ...")
                    
                # Run security header & cookie hardening checks
                header_gaps = analyze_security_headers(url, response.headers)
                for gap in header_gaps:
                    print(f"    └── {gap}")
            return
            
        except (httpx.RequestError, asyncio.TimeoutError) as e:
            if attempt == max_retries - 1:
                print(f"[-] [Error] Failed to reach {url} via {proxy or 'Direct'}: {e}")
            await asyncio.sleep(2)

async def run_stealth_scanner(target_url, endpoints):
    limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
    proxy_cycle = itertools.cycle(PROXY_LIST) if PROXY_LIST else None

    async with httpx.AsyncClient(limits=limits) as client:
        semaphore = asyncio.Semaphore(3)
        
        async def bounded_probe(ep):
            async with semaphore:
                proxy = next(proxy_cycle) if proxy_cycle else None
                await stealth_probe(client, target_url, ep, proxy=proxy)
                await asyncio.sleep(random.uniform(0.3, 0.9))

        tasks = [bounded_probe(ep) for ep in endpoints]
        await asyncio.gather(*tasks)
