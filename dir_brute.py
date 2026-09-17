import asyncio
import httpx
from urllib.parse import urljoin

# High-value sensitive directories, admin portals, config files, and backups
COMMON_PATHS = [
    "/admin/",
    "/administrator/",
    "/admin/login.php",
    "/api/",
    "/api/v1/",
    "/graphql",
    "/swagger-ui.html",
    "/openapi.json",
    "/phpmyadmin/",
    "/pma/",
    "/.env",
    "/config.json",
    "/config.php",
    "/settings.py",
    "/backup.zip",
    "/backup.tar.gz",
    "/site.bak",
    "/database.sql",
    "/server-status",
    "/git/config",
    "/.git/HEAD",
    "/wp-login.php",
    "/xmlrpc.php",
    "/robots.txt",
    "/sitemap.xml",
    "/debug/",
    "/test.php",
    "/info.php"
]

async def check_path(client, base_url, path, semaphore, findings, reporter):
    target_url = urljoin(base_url, path)
    async with semaphore:
        try:
            # Send GET request (do not follow redirects automatically to catch 301/302 redirects to login pages)
            response = await client.get(target_url, timeout=5.0, follow_redirects=False)
            status = response.status_code
            
            # Flag interesting HTTP statuses (200 OK, 403 Forbidden [exists but blocked], 301/302 Redirects)
            if status in [200, 403, 301, 302]:
                # Skip 403 if it's just a generic soft-403, but record it for high-value targets
                severity = "HIGH" if status == 200 and any(k in path for k in [".env", "backup", "sql", "git"]) else "MEDIUM"
                if status == 403:
                    severity = "LOW"
                
                desc = f"Discovered hidden endpoint/file: {target_url} [HTTP {status}]"
                print(f"[+] [HTTP {status}] {target_url}")
                
                findings.append({"path": path, "url": target_url, "status": status, "severity": severity})
                if reporter:
                    reporter.add_finding(
                        module="Directory Brute-Forcer",
                        severity=severity,
                        description=desc,
                        details={"url": target_url, "status_code": status}
                    )
        except Exception:
            pass

async def run_dir_brute(target_url, reporter=None):
    print(f"[*] Starting Async Directory & Content Brute-Forcing against: {target_url}")
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OffensiveBrute/2.0",
        "Accept": "*/*"
    }
    
    semaphore = asyncio.Semaphore(20) # Concurrency limit of 20 simultaneous requests
    findings = []
    
    async with httpx.AsyncClient(headers=headers, verify=False) as client:
        tasks = [check_path(client, target_url, path, semaphore, findings, reporter) for path in COMMON_PATHS]
        await asyncio.gather(*tasks)

    print("-" * 65)
    print(f"DIRECTORY BRUTE-FORCE SUMMARY")
    print("-" * 65)
    print(f"[*] Total Active Paths/Files Discovered: {len(findings)}")
    print("-" * 65)

    if reporter:
        reporter.add_section("Directory Brute-Force Analysis", {
            "target": target_url,
            "paths_checked": len(COMMON_PATHS),
            "findings_count": len(findings),
            "findings": findings
        })

    print("[*] Directory brute-force scanning completed successfully.")

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://medistore.se"
    asyncio.run(run_dir_brute(target))
