import asyncio
import aiohttp
from rich.console import Console

console = Console()

COMMON_GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/api",
    "/v1/graphql",
    "/query"
]

INTROSPECTION_QUERY = {
    "query": "{ __schema { queryType { name } types { name fields { name } } } }"
}

async def check_graphql_endpoint(session, base_url, path):
    url = base_url.rstrip("/") + path
    try:
        async with session.post(url, json=INTROSPECTION_QUERY, timeout=5) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                if "data" in data and data["data"] and "__schema" in data["data"]:
                    return url, True
    except Exception:
        pass
    return url, False

async def run_graphql_scan(target_url):
    """Probes for GraphQL endpoints and checks if introspection is enabled."""
    console.print(f"[bold cyan][*] Probing common GraphQL endpoints on {target_url}...[/bold cyan]")
    findings = []
    
    async with aiohttp.ClientSession() as session:
        tasks = [check_graphql_endpoint(session, target_url, path) for path in COMMON_GRAPHQL_PATHS]
        results = await asyncio.gather(*tasks)
        
        for url, introspection_enabled in results:
            if introspection_enabled:
                findings.append({
                    "endpoint": url,
                    "type": "GraphQL Introspection Enabled",
                    "severity": "Medium",
                    "details": "Introspection is enabled, allowing complete schema extraction."
                })
                console.print(f"[bold red][VULN FOUND] [MEDIUM] GraphQL Introspection Enabled at: {url}[/bold red]")
            else:
                console.print(f"[dim][-] Checked {url}: No active GraphQL introspection found.[/dim]")

    console.print(f"[bold green][+] GraphQL scan complete. Found {len(findings)} active endpoint(s) with introspection.[/bold green]")
    return findings
