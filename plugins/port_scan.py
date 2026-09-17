import asyncio
from urllib.parse import urlparse

PLUGIN_META = {
    "name": "Async Port & Banner Scanner",
    "flag": "--port-scan",
    "description": "Run async port and service banner scan",
    "category": "recon"
}

COMMON_PORTS = [21, 22, 80, 443, 8080, 8443, 3306, 27017]

async def check_port(host, port, findings, reporter):
    try:
        _, writer = await asyncio.open_connection(host, port)
        desc = f"Port {port} is OPEN on {host}"
        print(f"[+] [OPEN] {host}:{port}")
        findings.append({"port": port, "status": "open", "severity": "LOW"})
        if reporter:
            reporter.add_finding(module="Port Scanner", severity="LOW", description=desc, details={"port": port})
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass

async def run(target_url, reporter=None):
    parsed = urlparse(target_url)
    host = parsed.netloc.split(":")[0] if parsed.netloc else target_url
    print(f"[*] Starting Async Port Scan against host: {host}")
    
    findings = []
    tasks = [check_port(host, port, findings, reporter) for port in COMMON_PORTS]
    await asyncio.gather(*tasks)

    print(f"[*] Port scan completed. Open ports found: {len(findings)}")
    if reporter:
        reporter.add_section("Port Scan Analysis", {"host": host, "findings_count": len(findings), "findings": findings})
