def analyze_security_headers(url, headers):
    findings = []
    
    # Critical security headers to check
    expected_headers = {
        "Strict-Transport-Security": "Missing HSTS (Site vulnerable to protocol downgrade attacks)",
        "Content-Security-Policy": "Missing CSP (No defense against XSS or data injection)",
        "X-Frame-Options": "Missing X-Frame-Options (Vulnerable to Clickjacking)",
        "X-Content-Type-Options": "Missing X-Content-Type-Options (Vulnerable to MIME-sniffing)",
        "Permissions-Policy": "Missing Permissions-Policy (Browser features unrestrained)"
    }
    
    # Normalize header keys to lowercase for robust lookup
    lower_headers = {k.lower(): v for k, v in headers.items()}
    
    for header, warning in expected_headers.items():
        if header.lower() not in lower_headers:
            findings.append(f"[!] [Header Gap] {warning}")
            
    # Check Cookie security attributes if set
    set_cookie = lower_headers.get("set-cookie", "")
    if set_cookie:
        if "httponly" not in set_cookie.lower():
            findings.append("[!] [Cookie Flag] Cookie missing 'HttpOnly' attribute (Exposed to XSS theft)")
        if "secure" not in set_cookie.lower():
            findings.append("[!] [Cookie Flag] Cookie missing 'Secure' attribute (Sent over cleartext HTTP)")
            
    return findings
