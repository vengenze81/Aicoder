import asyncio
import httpx
from core.evasion import get_evasion_headers, apply_jitter

PLUGIN_META = {
    "name": "API Endpoint & Hidden Route Finder",
    "flag": "--api-finder",
    "description": "Scan for common API endpoints and documentation routes",
    "category": "recon"
}

COMMON_API_ROUTES = [
    "/api/v1/",
    "/api/v2/",
    "/api/",
    "/swagger.json",
    "/swagger-ui.html",
    "/openapi.json",
    "/graphql",
    "/api/users",
    "/api/health",
    "/api/status",
    "/v1/auth/login",
    "/api/v1/users",
    "/api-docs/"
]

async def check_route(client, base_url, route, findings, reporter):
    url = f"{base_url.rstrip('/')}{route}"
    try:
        await apply_jitter(0.1, 0.4)
        headers = get_evasion_headers()
        resp = await client.get(url, headers=headers, timeout=4.0)
        
        # HTTP 200, 401 (Auth required), 403 (Forbidden) often mean the route exists
        if resp.status_code in [200, 401, 403]:
            severity = "MEDIUM" if resp.status_code == 200 else "LOW"
            desc = f"Discovered API route/endpoint: {url} [HTTP {resp.status_code}]"
            print(f"[+] [HTTP {resp.status_code}] {url}")
            findings.append({"url": url, "status": resp.status_code, "severity": severity})
            if reporter:
                reporter.add_finding(
                    module="API Endpoint Finder",
                    severity=severity,
                    description=desc,
                    details={"endpoint": url, "status_code": resp.status_code}
                )
    except Exception:
        pass

async def run(target_url, reporter=None):
    print(f"[*] Starting API Endpoint & Hidden Route Finder against: {target_url}")
    findings = []
    
    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        tasks = [check_route(client, target_url, route, findings, reporter) for route in COMMON_API_ROUTES]
        await asyncio.gather(*tasks)

    print(f"[*] API route discovery completed. Active endpoints found: {len(findings)}")
    if reporter:
        reporter.add_section("API Endpoint Analysis", {"findings_count": len(findings), "findings": findings})
