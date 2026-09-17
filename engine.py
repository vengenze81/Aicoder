import asyncio
import httpx
import random
import re
import itertools
from config import USER_AGENTS, WAF_SIGNATURES, PROXY_LIST
from patterns import PATTERNS
from headers import analyze_security_headers
from crawler import extract_internal_links

async def analyze_content(url, text, headers):
    findings = []
    combined_data = text + " " + str(headers)
    for label, pattern in PATTERNS.items():
        matches = re.findall(pattern, combined_data)
        if matches:
            findings.append((label, matches))
    return findings

async def stealth_probe(client, base_url, endpoint, reporter=None, timeout=8.0, proxy=None, custom_headers=None, max_retries=3):
    url = base_url.rstrip("/") + endpoint
    base_delay = 1.5

    for attempt in range(max_retries):
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive"
        }
        
        if custom_headers:
            headers.update(custom_headers)
        
        try:
            kwargs = {"headers": headers, "timeout": timeout, "follow_redirects": True}
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

            new_links = []
            if response.status_code not in [404, 410]:
                route_type = f"Proxy: {proxy}" if proxy else "Direct"
                print(f"[+] [HTTP {response.status_code}] [{route_type}] Valid: {url} (Size: {len(response.content)})")
                
                regex_hits = []
                findings = await analyze_content(url, response.text, response.headers)
                for label, match_data in findings:
                    hit_str = f"{label}: {match_data[:3]}"
                    regex_hits.append(hit_str)
                    print(f"    └── [MATCH FOUND] {hit_str} ...")
                    
                header_gaps = analyze_security_headers(url, response.headers)
                for gap in header_gaps:
                    print(f"    └── {gap}")
                
                content_type = response.headers.get("content-type", "")
                if "text/html" in content_type:
                    new_links = extract_internal_links(base_url, response.text)
                
                if reporter:
                    reporter.add_result(
                        url=url,
                        status_code=response.status_code,
                        route_type=route_type,
                        size=len(response.content),
                        regex_matches=regex_hits,
                        header_gaps=header_gaps
                    )
            return response.status_code, new_links
            
        except (httpx.RequestError, asyncio.TimeoutError) as e:
            if attempt == max_retries - 1:
                print(f"[-] [Error] Failed to reach {url} via {proxy or 'Direct'}: {e}")
            await asyncio.sleep(2)
            
    return None, []

async def run_stealth_scanner(target_url, endpoints, recursive=False, max_crawl=40, reporter=None, concurrency=5, timeout=8.0, custom_headers=None):
    limits = httpx.Limits(max_keepalive_connections=concurrency, max_connections=concurrency * 2)
    proxy_cycle = itertools.cycle(PROXY_LIST) if PROXY_LIST else None

    visited = set()
    queue = list(endpoints)

    async with httpx.AsyncClient(limits=limits) as client:
        semaphore = asyncio.Semaphore(concurrency)
        
        async def process_endpoint(ep):
            if ep in visited:
                return
            visited.add(ep)
            
            async with semaphore:
                proxy = next(proxy_cycle) if proxy_cycle else None
                status, new_links = await stealth_probe(
                    client, target_url, ep, reporter=reporter, 
                    timeout=timeout, proxy=proxy, custom_headers=custom_headers
                )
                await asyncio.sleep(random.uniform(0.1, 0.3))
                
                if recursive and new_links and len(visited) < max_crawl:
                    for link in new_links:
                        if link not in visited and link not in queue:
                            queue.append(link)
                            print(f"    └── [Crawler] Discovered & queued new path: {link}")

        while queue and len(visited) < max_crawl:
            batch = queue[:concurrency * 2]
            del queue[:len(batch)]
            
            tasks = [process_endpoint(ep) for ep in batch]
            await asyncio.gather(*tasks)
