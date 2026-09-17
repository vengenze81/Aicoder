import asyncio
import httpx
from http.cookies import SimpleCookie
from core.evasion import get_evasion_headers, apply_jitter

PLUGIN_META = {
    "name": "Cookie & Session Security Auditor",
    "flag": "--session-audit",
    "description": "Inspect response cookies for missing security flags (HttpOnly, Secure, SameSite)",
    "category": "recon"
}

async def run(target_url, reporter=None):
    print(f"[*] Starting Cookie & Session Security Audit against: {target_url}")
    findings = []
    headers = get_evasion_headers()

    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        try:
            await apply_jitter(0.1, 0.3)
            resp = await client.get(target_url, headers=headers, timeout=5.0)
            
            # Extract Set-Cookie headers
            set_cookie_headers = []
            if hasattr(resp.headers, "get_list"):
                set_cookie_headers = resp.headers.get_list("set-cookie")
            elif "set-cookie" in resp.headers:
                set_cookie_headers = [resp.headers["set-cookie"]]

            print(f"[+] Retrieved {len(set_cookie_headers)} cookie(s) from target response.")

            for cookie_str in set_cookie_headers:
                cookie = SimpleCookie()
                cookie.load(cookie_str)
                
                for key, morsel in cookie.items():
                    secure = morsel.get("secure", "")
                    httponly = morsel.get("httponly", "")
                    samesite = morsel.get("samesite", "")

                    issues = []
                    if not secure:
                        issues.append("Missing 'Secure' flag")
                    if not httponly:
                        issues.append("Missing 'HttpOnly' flag")
                    if not samesite or samesite.lower() == "none":
                        issues.append(f"Insecure or missing 'SameSite' attribute ('{samesite}')")

                    if issues:
                        severity = "MEDIUM" if "HttpOnly" in str(issues) or "Secure" in str(issues) else "LOW"
                        desc = f"Insecure cookie configuration for '{key}': {'; '.join(issues)}"
                        print(f"[!] [{severity}] {desc}")
                        findings.append({
                            "cookie_name": key,
                            "issues": issues,
                            "severity": severity
                        })
                        if reporter:
                            reporter.add_finding(
                                module="Session Auditor",
                                severity=severity,
                                description=desc,
                                details={"cookie": key, "raw": cookie_str, "issues": issues}
                            )
                    else:
                        print(f"[+] [OK] Secure cookie configuration for '{key}'")

        except Exception as e:
            print(f"[-] Session audit failed: {e}")

    print(f"[*] Session audit completed. Cookie security issues flagged: {len(findings)}")
    if reporter:
        reporter.add_section("Cookie & Session Security Analysis", {"findings_count": len(findings), "findings": findings})
