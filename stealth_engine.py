import asyncio
import httpx
import random
import sys
import re

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"
]

WAF_SIGNATURES = ["attention required", "access denied", "cloudflare", "ddos-guard", "security check", "captcha"]

# Regex patterns for finding sensitive leaks and footprints
PATTERNS = {
    "API Key / Token": r"(?i)(api[_-]?key|access[_-]?token|bearer|auth[_-]?token)[\s'\"]*[:=][\s'\"]*([a-zA-Z0-9_\-\.]{16,64})",
    "Database Error": r"(?i)(sql syntax.*MySQL|unclosed quotation mark|pg_query|syntax error in SQL|sqlite3\.OperationalError)",
    "Private Key": r"-----BEGIN (?:RSA|PRIVATE) KEY-----",
    "Email Address": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "WordPress Version": r"wp-includes/js/wp-embed\.min\.js\?ver=([0-9\.]+)"
}

async def analyze_content(url, text, headers):
    findings = []
    combined_data = text + " " + str(headers)
    
    for label, pattern in PATTERNS.items():
        matches = re.findall(pattern, combined_data)
        if matches:
            findings.append((label, matches))
            
    return findings

async def stealth_probe(client, base_url, endpoint, max_retries=3):
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
            response = await client.get(url, headers=headers, timeout=8.0, follow_redirects=True)
            body_lower = response.text.lower()

            is_blocked = (
                response.status_code in [429, 503] or 
                (response.status_code == 403 and any(sig in body_lower for sig in WAF_SIGNATURES))
            )

            if is_blocked:
                jitter = random.uniform(0.5, 2.0)
                sleep_time = (base_delay * (2 ** attempt)) + jitter
                print(f"[!] [WAF/Rate-Limit] Blocked on {url} (HTTP {response.status_code}). Backing off for {sleep_time:.2f}s...")
                await asyncio.sleep(sleep_time)
                continue

            if response.status_code not in [404, 410]:
                print(f"[+] [HTTP {response.status_code}] Valid: {url} (Size: {len(response.content)})")
                
                # Execute regex grep analysis on response body/headers
                findings = await analyze_content(url, response.text, response.headers)
                for label, match_data in findings:
                    print(f"    └── [MATCH FOUND] {label}: {match_data[:3]} ...")
            return
            
        except (httpx.RequestError, asyncio.TimeoutError):
            if attempt == max_retries - 1:
                print(f"[-] [Timeout/Error] Failed to reach: {url}")
            await asyncio.sleep(2)

async def run_stealth_scanner(target_url, endpoints):
    limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
    async with httpx.AsyncClient(limits=limits) as client:
        semaphore = asyncio.Semaphore(3)
        
        async def bounded_probe(ep):
            async with semaphore:
                await stealth_probe(client, target_url, ep)
                await asyncio.sleep(random.uniform(0.3, 0.9))

        tasks = [bounded_probe(ep) for ep in endpoints]
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://medistore.se"
    test_endpoints = ["/", "/robots.txt", "/sitemap.xml", "/wp-login.php", "/wp-json/wp/v2/users", "/cart"]
    
    print(f"[*] Initializing Stealth Engine with Regex Grep against: {target}\n")
    asyncio.run(run_stealth_scanner(target, test_endpoints))
