import asyncio
import httpx
from core.evasion import get_evasion_headers

PLUGIN_META = {
    "name": "HTTP Security Header Auditor",
    "flag": "--header-audit",
    "description": "Audit HTTP response headers for missing security controls",
    "category": "recon"
}

REQUIRED_HEADERS = {
    "Strict-Transport-Security": {"severity": "MEDIUM", "desc": "HSTS missing (Vulnerable to protocol downgrade attacks)"},
    "Content-Security-Policy": {"severity": "MEDIUM", "desc": "CSP missing (Vulnerable to XSS and data injection)"},
    "X-Frame-Options": {"severity": "LOW", "desc": "X-Frame-Options missing (Vulnerable to clickjacking)"},
    "X-Content-Type-Options": {"severity": "LOW", "desc": "X-Content-Type-Options missing (Vulnerable to MIME-sniffing)"},
    "Referrer-Policy": {"severity": "LOW", "desc": "Referrer-Policy missing (Potential information leakage in referrer header)"}
}

async def run(target_url, reporter=None):
    print(f"[*] Starting HTTP Security Header Audit against: {target_url}")
    findings = []
    headers = get_evasion_headers()

    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        try:
            resp = await client.get(target_url, headers=headers, timeout=5.0)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            
            print(f"[+] Retrieved response headers from target.")
            
            for header, info in REQUIRED_HEADERS.items():
                if header.lower() not in resp_headers:
                    print(f"[!] [{info['severity']}] Missing header: {header}")
                    findings.append({
                        "header": header,
                        "status": "Missing",
                        "severity": info["severity"],
                        "description": info["desc"]
                    })
                    if reporter:
                        reporter.add_finding(
                            module="Header Auditor",
                            severity=info["severity"],
                            description=info["desc"],
                            details={"missing_header": header}
                        )
                else:
                    print(f"[+] [OK] Found header: {header} -> {resp_headers[header.lower()]}")
                    
        except Exception as e:
            print(f"[-] Header audit failed: {e}")

    print(f"[*] Header audit completed. Missing security headers flagged: {len(findings)}")
    if reporter:
        reporter.add_section("HTTP Security Header Analysis", {"findings_count": len(findings), "findings": findings})
