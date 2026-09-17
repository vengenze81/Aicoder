import asyncio
import httpx
from urllib.parse import urljoin

PLUGIN_META = {
    "name": "Async Directory Brute-Forcer",
    "flag": "--dir-brute",
    "description": "Run async directory and content brute-forcer",
    "category": "offensive"
}

COMMON_PATHS = [
    "/admin/", "/administrator/", "/api/", "/graphql", "/swagger-ui.html",
    "/.env", "/config.json", "/config.php", "/backup.zip", "/database.sql",
    "/.git/HEAD", "/wp-login.php", "/xmlrpc.php", "/robots.txt", "/sitemap.xml"
]

async def check_path(client, base_url, path, semaphore, findings, reporter):
    target_url = urljoin(base_url, path)
    async with semaphore:
        try:
            resp = await client.get(target_url, timeout=5.0, follow_redirects=False)
            if resp.status_code in [200, 403, 301, 302]:
                severity = "HIGH" if resp.status_code == 200 and any(k in path for k in [".env", "backup", "sql", "git"]) else "MEDIUM"
                if resp.status_code == 403: severity = "LOW"
                desc = f"Discovered hidden path: {target_url} [HTTP {resp.status_code}]"
                print(f"[+] [HTTP {resp.status_code}] {target_url}")
                findings.append({"url": target_url, "status": resp.status_code, "severity": severity})
                if reporter:
                    reporter.add_finding(module="Directory Brute-Forcer", severity=severity, description=desc, details={"url": target_url, "status": resp.status_code})
        except Exception:
            pass

async def run(target_url, reporter=None):
    print(f"[*] Starting Async Directory Brute-Forcing against: {target_url}")
    headers = {"User-Agent": "Mozilla/5.0 OffensiveBrute/3.0"}
    semaphore = asyncio.Semaphore(20)
    findings = []
    
    async with httpx.AsyncClient(headers=headers, verify=False) as client:
        tasks = [check_path(client, target_url, path, semaphore, findings, reporter) for path in COMMON_PATHS]
        await asyncio.gather(*tasks)

    print(f"[*] Directory brute-force completed. Discovered: {len(findings)}")
    if reporter:
        reporter.add_section("Directory Brute-Force Analysis", {"findings_count": len(findings), "findings": findings})
