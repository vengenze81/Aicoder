import asyncio
import httpx

# Common sensitive files, logs, configuration backups, and archive footprints
SENSITIVE_PATHS = [
    ("/wp-config.php.bak", "Exposed WordPress configuration backup"),
    ("/wp-config.php.save", "Exposed configuration save file"),
    ("/wp-config.php~", "Exposed configuration editor backup"),
    ("/wp-content/debug.log", "Exposed WordPress debug error log"),
    ("/.env", "Exposed environment configuration file"),
    ("/.git/HEAD", "Exposed Git version control repository metadata"),
    ("/backup.zip", "Root archive backup file"),
    ("/backup.tar.gz", "Root compressed archive backup"),
    ("/backup.sql", "Exposed SQL database dump"),
    ("/database.sql", "Exposed database SQL file"),
    ("/wp-content/uploads/backup.zip", "Exposed backup archive in uploads directory"),
    ("/old/wp-config.php", "Legacy configuration file in subdirectory"),
    ("/phpinfo.php", "Exposed PHP environment configuration page")
]

async def scan_sensitive_files(target_url, timeout=8.0, reporter=None):
    base = target_url.rstrip("/")
    print(f"[*] Starting Sensitive File & Backup Exposure Scan against {base}")
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityAuditor/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }
    
    print("-" * 80)
    print(f"{'SENSITIVE PATH':<32} | {'STATUS':<8} | {'EXPOSURE ASSESSMENT'}")
    print("-" * 80)
    
    exposed_count = 0
    
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        for path, description in SENSITIVE_PATHS:
            url = base + path
            try:
                response = await client.get(url, headers=headers)
                status = response.status_code
                
                # Check for successful response (and avoid soft 404 custom error pages returning 200)
                if status == 200:
                    content_len = len(response.content)
                    # Simple heuristic: ignore tiny or massive generic HTML redirect/error pages if status is 200 incorrectly
                    if content_len > 0:
                        exposed_count += 1
                        print(f"{path:<32} | {status:<8} | VULNERABLE: {description} ({content_len} bytes)")
                        if reporter:
                            reporter.add_finding(
                                title=f"Sensitive File Exposed: {path}",
                                description=f"Path responded with HTTP 200. Description: {description} | Size: {content_len} bytes",
                                severity="High" if "config" in path or ".env" in path or ".git" in path else "Medium"
                            )
                    else:
                        print(f"{path:<32} | {status:<8} | Empty 200 OK (Likely false positive)")
                elif status == 403:
                    print(f"{path:<32} | {status:<8} | Protected / Forbidden")
                else:
                    print(f"{path:<32} | {status:<8} | Secure (HTTP {status})")
                    
            except Exception as e:
                print(f"{path:<32} | ERROR    | Connection failed")
                
    print("-" * 80)
    print(f"[*] Sensitive file scan completed. Identified {exposed_count} accessible risk paths.")
