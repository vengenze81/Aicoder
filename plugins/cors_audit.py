import asyncio
import httpx

PLUGIN_META = {
    "name": "CORS Misconfiguration Auditor",
    "flag": "--cors-audit",
    "description": "Audit for Cross-Origin Resource Sharing (CORS) misconfigurations",
    "category": "offensive"
}

TEST_ORIGINS = [
    "https://evil.com",
    "null",
    "https://medistore.se.evil.com",
    "http://localhost:3000"
]

async def run(target_url, reporter=None):
    print(f"[*] Starting CORS Misconfiguration Audit against: {target_url}")
    findings = []
    
    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        for origin in TEST_ORIGINS:
            headers = {
                "User-Agent": "Mozilla/5.0 CORSAuditor/3.0",
                "Origin": origin
            }
            try:
                resp = await client.get(target_url, headers=headers, timeout=5.0)
                acao = resp.headers.get("Access-Control-Allow-Origin")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
                
                if acao:
                    vulnerable = False
                    severity = "LOW"
                    desc = f"CORS header returned with Origin '{origin}' -> ACAO: '{acao}', Credentials: {acac}"
                    
                    # Check for dangerous patterns
                    if acao == "*" and acac:
                        vulnerable = True
                        severity = "CRITICAL"
                        desc = f"[CRITICAL] Wildcard CORS (*) with Credentials allowed for origin: {origin}"
                    elif acao == origin and acac:
                        vulnerable = True
                        severity = "HIGH"
                        desc = f"[HIGH] Arbitrary Origin reflection with Credentials allowed: {acao}"
                    elif acao == "null":
                        vulnerable = True
                        severity = "MEDIUM"
                        desc = f"[MEDIUM] Dangerous 'null' origin reflection allowed."

                    if vulnerable:
                        print(f"[!] {desc}")
                        findings.append({"url": target_url, "tested_origin": origin, "acao": acao, "credentials": acac, "severity": severity})
                        if reporter:
                            reporter.add_finding(
                                module="CORS Auditor",
                                severity=severity,
                                description=desc,
                                details={"tested_origin": origin, "acao": acao, "allow_credentials": acac}
                            )
                    else:
                        print(f"[+] [INFO] {desc}")
            except Exception as e:
                pass

    print(f"[*] CORS audit completed. Misconfigurations found: {len(findings)}")
    if reporter:
        reporter.add_section("CORS Audit Analysis", {"findings_count": len(findings), "findings": findings})
