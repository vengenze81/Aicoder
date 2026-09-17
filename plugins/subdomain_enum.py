import asyncio
import httpx
from urllib.parse import urlparse

PLUGIN_META = {
    "name": "Async Subdomain Enumerator",
    "flag": "--sub-enum",
    "description": "Enumerate common subdomains asynchronously",
    "category": "recon"
}

COMMON_SUBDOMAINS = [
    "www", "mail", "admin", "api", "portal", "test", 
    "staging", "shop", "blog", "vpn", "support", "dev",
    "dashboard", "auth", "login", "cloud", "status", "api-docs"
]

async def check_subdomain(client, subdomain, domain, findings, reporter):
    url = f"https://{subdomain}.{domain}"
    try:
        resp = await client.get(url, timeout=3.0)
        if resp.status_code < 500:
            desc = f"Discovered active subdomain: {url} [HTTP {resp.status_code}]"
            print(f"[+] [HTTP {resp.status_code}] {url}")
            findings.append({"subdomain": url, "status": resp.status_code, "severity": "LOW"})
            if reporter:
                reporter.add_finding(
                    module="Subdomain Enumerator",
                    severity="LOW",
                    description=desc,
                    details={"subdomain_url": url, "status_code": resp.status_code}
                )
    except Exception:
        pass

async def run(target_url, reporter=None):
    print(f"[*] Starting Async Subdomain Enumeration...")
    parsed = urlparse(target_url)
    netloc = parsed.netloc or target_url
    domain = netloc.split(":")[0]
    
    # Extract root domain (e.g., medistore.se from sub.medistore.se)
    parts = domain.split(".")
    if len(parts) > 2:
        base_domain = ".".join(parts[-2:])
    else:
        base_domain = domain

    print(f"[*] Target base domain: {base_domain}")
    findings = []
    headers = {"User-Agent": "Mozilla/5.0 SubdomainEnumerator/3.0"}

    async with httpx.AsyncClient(headers=headers, verify=False, follow_redirects=True) as client:
        tasks = [check_subdomain(client, sub, base_domain, findings, reporter) for sub in COMMON_SUBDOMAINS]
        await asyncio.gather(*tasks)

    print(f"[*] Subdomain enumeration completed. Active subdomains found: {len(findings)}")
    if reporter:
        reporter.add_section("Subdomain Enumeration Analysis", {"base_domain": base_domain, "findings_count": len(findings), "findings": findings})
