import asyncio
import httpx
from urllib.parse import urljoin

# Common high-value API documentation and schema endpoints
COMMON_API_PATHS = [
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/api/docs",
    "/api/v1/docs",
    "/graphql",
    "/api/v1/",
    "/api/",
    "/api/swagger.ui",
    "/swagger-ui.html",
    "/v1/api-docs"
]

async def check_api_endpoint(client, base_url, path, reporter=None):
    url = urljoin(base_url, path)
    try:
        response = await client.get(url, timeout=4.0, follow_redirects=True)
        status = response.status_code
        # Flag if endpoint exists (200 OK or auth-required 401/403)
        if status in [200, 401, 403]:
            print(f"[+] Discovered API Endpoint/Doc: {url} [HTTP {status}]")
            if reporter:
                reporter.add_finding(
                    module="API Endpoint Discovery",
                    severity="INFO" if status != 200 else "WARNING",
                    description=f"Exposed API path found: {url} (HTTP {status})",
                    details={"url": url, "status_code": status, "content_type": response.headers.get("content-type", "")}
                )
            return {"url": url, "status": status}
    except Exception:
        pass
    return None

async def discover_api_endpoints(target_url, reporter=None):
    """
    Asynchronously checks for common API documentation and endpoint paths.
    """
    print(f"[*] Starting API Endpoint & Documentation Discovery against: {target_url}")
    print(f"[*] Probing {len(COMMON_API_PATHS)} common API and documentation paths...")

    discovered = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityAuditor/2.0"}

    async with httpx.AsyncClient(headers=headers, verify=False) as client:
        tasks = [check_api_endpoint(client, target_url, path, reporter) for path in COMMON_API_PATHS]
        results = await asyncio.gather(*tasks)
        discovered = [r for r in results if r is not None]

    print("-" * 65)
    print(f"API DISCOVERY SUMMARY")
    print("-" * 65)
    print(f"[*] Total API Endpoints/Docs Discovered: {len(discovered)}")
    for d in discovered:
        print(f"    - {d['url']} [HTTP {d['status']}]")
    print("-" * 65)

    if reporter:
        reporter.add_section("API Endpoint Discovery", {
            "target": target_url,
            "total_discovered": len(discovered),
            "endpoints": discovered
        })

    print("[*] API endpoint discovery completed successfully.")

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://medistore.se"
    asyncio.run(discover_api_endpoints(target))
