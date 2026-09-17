import asyncio
import httpx
from urllib.parse import urljoin

GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/query",
    "/api",
    "/v2/graphql"
]

INTROSPECTION_QUERY = {
    "query": """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          name
          kind
          description
          fields {
            name
            description
          }
        }
      }
    }
    """
}

async def probe_graphql_endpoint(client, target_url, findings, reporter):
    try:
        response = await client.post(target_url, json=INTROSPECTION_QUERY, timeout=8.0)
        if response.status_code == 200:
            data = response.json()
            if "data" in data and data["data"] and "__schema" in data["data"]:
                desc = f"GraphQL Introspection is ENABLED, exposing full database schema at: {target_url}"
                print(f"[!] [CRITICAL] {desc}")
                findings.append({
                    "url": target_url,
                    "introspection_enabled": True,
                    "severity": "CRITICAL"
                })
                if reporter:
                    reporter.add_finding(
                        module="GraphQL Auditor",
                        severity="CRITICAL",
                        description=desc,
                        details={"endpoint": target_url, "schema_exposed": True}
                    )
                return True
            elif "errors" in data:
                # Endpoint exists and responds to GraphQL, but introspection might be restricted
                desc = f"GraphQL endpoint active (returned validation/execution error) at: {target_url}"
                print(f"[+] [INFO] {desc}")
                findings.append({
                    "url": target_url,
                    "introspection_enabled": False,
                    "severity": "LOW"
                })
        elif response.status_code in [400, 405]:
            desc = f"Potential GraphQL endpoint detected (HTTP {response.status_code}) at: {target_url}"
            print(f"[+] [INFO] {desc}")
    except Exception:
        pass
    return False

async def run_graphql_audit(target_url, reporter=None):
    print(f"[*] Starting GraphQL Introspection & Schema Audit against: {target_url}")
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) GraphQLAuditor/2.0",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    findings = []
    base_urls_to_test = [target_url]
    
    # Also append common paths to the base domain
    from urllib.parse import urlparse
    parsed = urlparse(target_url)
    root_base = f"{parsed.scheme}://{parsed.netloc}"
    for path in GRAPHQL_PATHS:
        base_urls_to_test.append(urljoin(root_base, path))

    async with httpx.AsyncClient(headers=headers, verify=False, follow_redirects=True) as client:
        for url in base_urls_to_test:
            await probe_graphql_endpoint(client, url, findings, reporter)

    print("-" * 65)
    print(f"GRAPHQL AUDIT SUMMARY")
    print("-" * 65)
    print(f"[*] Total GraphQL Findings / Endpoints Flagged: {len(findings)}")
    print("-" * 65)

    if reporter:
        reporter.add_section("GraphQL Audit Analysis", {
            "target": target_url,
            "findings_count": len(findings),
            "findings": findings
        })

    print("[*] GraphQL security audit completed.")

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://medistore.se"
    asyncio.run(run_graphql_audit(target))
