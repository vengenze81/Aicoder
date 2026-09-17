import asyncio
import httpx
from urllib.parse import urlparse

# Common high-value subdomains for reconnaissance
COMMON_SUBDOMAINS = [
    "admin", "api", "staging", "dev", "test", "shop", "store", 
    "portal", "auth", "login", "dashboard", "app", "secure", 
    "vpn", "mail", "ftp", "blog", "status", "support", "git"
]

async def check_subdomain(client, domain, subdomain, reporter=None):
    url = f"https://{subdomain}.{domain}"
    try:
        response = await client.get(url, timeout=4.0, follow_redirects=True)
        status = response.status_code
        print(f"[+] Discovered Subdomain: {url} [HTTP {status}]")
        if reporter:
            reporter.add_finding(
                module="Subdomain Enumeration",
                severity="INFO",
                description=f"Active subdomain found: {url} (HTTP {status})",
                details={"subdomain": url, "status_code": status}
            )
        return url
    except Exception:
        # Fallback to http if https fails
        http_url = f"http://{subdomain}.{domain}"
        try:
            response = await client.get(http_url, timeout=3.0, follow_redirects=True)
            status = response.status_code
            print(f"[+] Discovered Subdomain: {http_url} [HTTP {status}]")
            if reporter:
                reporter.add_finding(
                    module="Subdomain Enumeration",
                    severity="INFO",
                    description=f"Active subdomain found: {http_url} (HTTP {status})",
                    details={"subdomain": http_url, "status_code": status}
                )
            return http_url
        except Exception:
            pass
    return None

async def enumerate_subdomains(target_url, reporter=None):
    """
    Asynchronously checks common subdomains against the target domain root.
    """
    parsed = urlparse(target_url)
    netloc = parsed.netloc or parsed.path
    # Strip www or port if present
    domain = netloc.split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]

    print(f"[*] Starting Subdomain Enumeration against base domain: {domain}")
    print(f"[*] Probing {len(COMMON_SUBDOMAINS)} common structural subdomains...")

    discovered = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityAuditor/2.0"}

    async with httpx.AsyncClient(headers=headers, verify=False) as client:
        tasks = [check_subdomain(client, domain, sub, reporter) for sub in COMMON_SUBDOMAINS]
        results = await asyncio.gather(*tasks)
        discovered = [r for r in results if r is not None]

    print("-" * 60)
    print(f"SUBDOMAIN ENUMERATION SUMMARY")
    print("-" * 60)
    print(f"[*] Total Active Subdomains Discovered: {len(discovered)}")
    for d in discovered:
        print(f"    - {d}")
    print("-" * 60)

    if reporter:
        reporter.add_section("Subdomain Enumeration", {
            "base_domain": domain,
            "total_discovered": len(discovered),
            "subdomains": discovered
        })

    print("[*] Subdomain enumeration completed successfully.")

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://medistore.se"
    asyncio.run(enumerate_subdomains(target))
