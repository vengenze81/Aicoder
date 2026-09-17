import asyncio
import httpx

PLUGIN_META = {
    "name": "WAF Rate-Limit & Concurrency Profiler",
    "flag": "--waf-profile",
    "description": "Profile WAF rate-limiting and behavior",
    "category": "recon"
}

async def run(target_url, reporter=None):
    print(f"[*] Starting WAF Profiling against: {target_url}")
    headers = {"User-Agent": "Mozilla/5.0 WAFProfiler/3.0"}
    
    blocked = False
    async with httpx.AsyncClient(headers=headers, verify=False, follow_redirects=True) as client:
        try:
            # Send rapid concurrent requests to test rate-limiting / WAF triggering
            tasks = [client.get(target_url, timeout=4.0) for _ in range(15)]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            status_codes = [r.status_code for r in responses if isinstance(r, httpx.Response)]
            print(f"[+] Concurrency status codes observed: {set(status_codes)}")
            
            if 403 in status_codes or 429 in status_codes:
                blocked = True
                print(f"[!] [INFO] WAF or Rate-Limiting detected (HTTP 403/429 triggered under load).")
        except Exception as e:
            print(f"[-] WAF profiler encountered exception: {e}")

    if reporter:
        reporter.add_section("WAF Profile Analysis", {"target": target_url, "waf_triggered": blocked})
    print(f"[*] WAF profiling completed.")
