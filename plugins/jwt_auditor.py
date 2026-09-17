import asyncio
import httpx
import re
import base64
import json
import hmac
import hashlib

PLUGIN_META = {
    "name": "JWT Security & Weak Secret Auditor",
    "flag": "--jwt-audit",
    "description": "Audit JSON Web Tokens for weak secrets and signature flaws",
    "category": "offensive"
}

COMMON_SECRETS = [
    "secret", "password", "jwtsecret", "123456", "admin", 
    "supersecret", "key", "changeme", "test", "12345678"
]

JWT_REGEX = re.compile(r'eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+')

def decode_jwt_part(part):
    try:
        padding = '=' * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part + padding).decode('utf-8'))
    except Exception:
        return {}

def test_weak_secret(token_parts, signature_bytes):
    header_b64, payload_b64, _ = token_parts
    message = f"{header_b64}.{payload_b64}".encode('utf-8')
    
    for secret in COMMON_SECRETS:
        try:
            h = hmac.new(secret.encode('utf-8'), message, hashlib.sha256).digest()
            sig_encoded = base64.urlsafe_b64encode(h).rstrip(b'=').decode('utf-8')
            if sig_encoded == _:
                return secret
        except Exception:
            pass
    return None

async def run(target_url, reporter=None):
    print(f"[*] Starting JWT Security & Secret Audit against: {target_url}")
    findings = []
    found_tokens = set()

    headers = {"User-Agent": "Mozilla/5.0 JWTAuditor/3.0"}
    
    async with httpx.AsyncClient(headers=headers, verify=False, follow_redirects=True) as client:
        try:
            resp = await client.get(target_url, timeout=6.0)
            # Search cookies and body text for JWTs
            cookies_str = str(resp.cookies.items())
            body_text = resp.text
            
            for match in JWT_REGEX.findall(body_text + cookies_str):
                found_tokens.add(match)
        except Exception as e:
            print(f"[-] Failed to fetch target for JWT extraction: {e}")

    if not found_tokens:
        print("[*] No active JWTs detected in public headers or cookies. Simulating token check...")
        # If no token found on medistore.se, log standard informational scan result
        if reporter:
            reporter.add_section("JWT Audit Analysis", {"target": target_url, "tokens_found": 0, "status": "No public JWTs exposed"})
        print(f"[*] JWT security audit completed. Findings: 0")
        return

    print(f"[+] Discovered {len(found_tokens)} unique JWT(s). Analyzing security posture...")

    for token in found_tokens:
        parts = token.split('.')
        if len(parts) != 3:
            continue
        
        header = decode_jwt_part(parts[0])
        payload = decode_jwt_part(parts[1])
        alg = header.get("alg", "unknown")
        
        print(f"[+] Analyzed Token - Algorithm: {alg}, Payload: {payload}")

        # Check for 'none' algorithm vulnerability
        if alg.lower() == "none":
            desc = f"CRITICAL: JWT allows 'none' signature algorithm (Signature Bypass): {token[:20]}..."
            print(f"[!] [CRITICAL] {desc}")
            findings.append({"token_sample": token[:20], "vulnerability": "Alg None Bypass", "severity": "CRITICAL"})
            if reporter:
                reporter.add_finding(module="JWT Auditor", severity="CRITICAL", description=desc, details={"alg": "none"})
        
        # Check for weak HMAC secrets if HS256
        elif alg.upper() == "HS256":
            cracked_secret = test_weak_secret(parts, parts[2])
            if cracked_secret:
                desc = f"HIGH: JWT signed with weak/default HMAC secret '{cracked_secret}': {token[:20]}..."
                print(f"[!] [HIGH] {desc}")
                findings.append({"token_sample": token[:20], "vulnerability": "Weak HMAC Secret", "secret": cracked_secret, "severity": "HIGH"})
                if reporter:
                    reporter.add_finding(module="JWT Auditor", severity="HIGH", description=desc, details={"cracked_secret": cracked_secret})
            else:
                print(f"[-] HMAC secret brute-force: No weak secrets matched in dictionary.")

    print(f"[*] JWT audit completed. Vulnerabilities found: {len(findings)}")
    if reporter:
        reporter.add_section("JWT Audit Analysis", {"tokens_analyzed": len(found_tokens), "findings_count": len(findings), "findings": findings})
