import asyncio
import time
import httpx

async def profile_waf(target_url, timeout=5.0, reporter=None):
    base = target_url.rstrip("/")
    print(f"[*] Starting WAF Rate-Limit Auto-Tune Profiler against {base}")
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityAuditor/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }
    
    print("-" * 80)
    print(f"{'CONCURRENCY':<15} | {'DELAY (s)':<10} | {'RESPONSE BREAKDOWN':<30} | {'WAF STATUS'}")
    print("-" * 80)
    
    # Escalating bursts of requests to test throughput thresholds
    test_steps = [
        {"concurrency": 2, "delay": 0.3, "requests": 8},
        {"concurrency": 5, "delay": 0.1, "requests": 12},
        {"concurrency": 12, "delay": 0.02, "requests": 20},
        {"concurrency": 25, "delay": 0.0, "requests": 35},
    ]
    
    optimal_concurrency = 5
    optimal_delay = 0.1
    waf_triggered = False
    
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        for step in test_steps:
            conc = step["concurrency"]
            delay = step["delay"]
            req_count = step["requests"]
            
            async def send_single_req():
                start_t = time.time()
                try:
                    resp = await client.get(base, headers=headers)
                    return resp.status_code, time.time() - start_t
                except Exception:
                    return 0, 0.0

            semaphore = asyncio.Semaphore(conc)
            
            async def bounded_req():
                async with semaphore:
                    if delay > 0:
                        await asyncio.sleep(delay)
                    return await send_single_req()

            tasks = [bounded_req() for _ in range(req_count)]
            results = await asyncio.gather(*tasks)
            
            status_counts = {}
            blocked = False
            for status, lat in results:
                status_counts[status] = status_counts.get(status, 0) + 1
                if status in [429, 403, 503]:
                    blocked = True

            status_summary = ", ".join([f"HTTP {k}: {v}" for k, v in status_counts.items()])
            
            if blocked:
                print(f"{conc:<15} | {delay:<10} | {status_summary:<30} | THRESHOLD REACHED")
                waf_triggered = True
                break
            else:
                print(f"{conc:<15} | {delay:<10} | {status_summary:<30} | Safe / Unrestricted")
                optimal_concurrency = conc
                optimal_delay = delay
                
    print("-" * 80)
    if waf_triggered:
        recommended_c = max(1, optimal_concurrency - 2)
        print(f"[*] Rate-limit threshold identified! Recommended safe concurrency: {recommended_c} with delay >= {optimal_delay}s.")
        if reporter:
            reporter.add_finding(
                title="WAF Rate-Limit Threshold Detected",
                description=f"Rate limiting or blocking triggered around concurrency {optimal_concurrency}. Recommended safe concurrency: {recommended_c}.",
                severity="Info"
            )
    else:
        print(f"[*] No strict rate limiting triggered up to concurrency 25. Target appears lenient.")
        if reporter:
            reporter.add_finding(
                title="WAF Rate-Limit Profile Completed",
                description="No strict rate-limiting detected up to concurrency 25.",
                severity="Info"
            )
