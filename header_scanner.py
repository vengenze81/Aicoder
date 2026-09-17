import asyncio
import httpx

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS (Enforces secure HTTPS transport)",
    "content-security-policy": "CSP (Mitigates XSS and data injection attacks)",
    "x-frame-options": "X-Frame-Options (Protects against Clickjacking)",
    "x-content-type-options": "X-Content-Type-Options (Prevents MIME-sniffing)",
    "referrer-policy": "Referrer-Policy (Controls referrer information leakage)",
    "permissions-policy": "Permissions-Policy (Restricts browser feature access)"
}

async def scan_security_headers(target_url, timeout=8.0, reporter=None):
    base = target_url.rstrip("/")
    print(f"[*] Starting HTTP Security Headers & Transport Audit against {base}")
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityAuditor/1.0"
    }
    
    print("-" * 80)
    print(f"{'SECURITY HEADER':<30} | {'STATUS':<10} | {'DESCRIPTION / RISK ASSESSMENT'}")
    print("-" * 80)
    
    missing_count = 0
    present_count = 0
    
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        try:
            response = await client.get(base, headers=headers)
            resp_headers = {k.lower(): v for k, v in response.headers.items()}
            
            for header_key, description in SECURITY_HEADERS.items():
                if header_key in resp_headers:
                    present_count += 1
                    val = resp_headers[header_key]
                    print(f"{header_key:<30} | PRESENT    | {description}")
                    if reporter:
                        reporter.add_finding(
                            title=f"Security Header Present: {header_key}",
                            description=f"Header is configured. Value: {val[:60]}...",
                            severity="Info"
                        )
                else:
                    missing_count += 1
                    print(f"{header_key:<30} | MISSING    | Recommended: {description}")
                    if reporter:
                        reporter.add_finding(
                            title=f"Missing Security Header: {header_key}",
                            description=f"The target response is missing the {header_key} header, reducing client-side hardening.",
                            severity="Low" if header_key in ["x-frame-options", "x-content-type-options"] else "Medium"
                        )
                        
            is_https = base.startswith("https://")
            print("-" * 80)
            print(f"[*] Transport Encryption (HTTPS): {'Active' if is_https else 'WARNING: Plaintext HTTP'}")
            
        except Exception as e:
            print(f"[-] Error connecting to target: {e}")
            
    print(f"[*] Header audit completed. Present: {present_count}, Missing: {missing_count}.")
