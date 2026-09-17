import asyncio
import httpx
from urllib.parse import urljoin, urlparse

PLUGIN_META = {
    "name": "GraphQL Introspection Auditor",
    "flag": "--graphql-audit",
    "description": "Run GraphQL introspection and schema auditor",
    "category": "offensive"
}

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/api", "/v2/graphql"]
INTROSPECTION_QUERY = {
    "query": """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types { name kind fields { name } }
      }
    }
    """
}

async def run(target_url, reporter=None):
    print(f"[*] Starting GraphQL Introspection & Schema Audit against: {target_url}")
    headers = {"User-Agent": "Mozilla/5.0 OffensiveAuditor/3.0", "Content-Type": "application/json"}
    findings = []
    
    parsed = urlparse(target_url)
    root_base = f"{parsed.scheme}://{parsed.netloc}"
    urls_to_test = [target_url] + [urljoin(root_base, p) for p in GRAPHQL_PATHS]

    async with httpx.AsyncClient(headers=headers, verify=False, follow_redirects=True) as client:
        for url in urls_to_test:
            try:
                resp = await client.post(url, json=INTROSPECTION_QUERY, timeout=6.0)
                if resp.status_code == 200:
                    data = resp.json()
                    if "data" in data and data["data"] and "__schema" in data["data"]:
                        desc = f"GraphQL Introspection is ENABLED at: {url}"
                        print(f"[!] [CRITICAL] {desc}")
                        findings.append({"url": url, "severity": "CRITICAL"})
                        if reporter:
                            reporter.add_finding(module="GraphQL Auditor", severity="CRITICAL", description=desc, details={"endpoint": url})
            except Exception:
                pass

    print(f"[*] GraphQL audit completed. Findings: {len(findings)}")
    if reporter:
        reporter.add_section("GraphQL Audit Analysis", {"findings_count": len(findings), "findings": findings})
