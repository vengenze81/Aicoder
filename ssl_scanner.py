import asyncio
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

def _sync_audit_ssl(host, port):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    ssl_info = {}
    findings = []
    
    with socket.create_connection((host, port), timeout=5.0) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()
            version = ssock.version()
            
            ssl_info["tls_version"] = version
            ssl_info["cipher"] = cipher
            
            subject = dict(x[0] for x in cert.get('subject', []))
            issuer = dict(x[0] for x in cert.get('issuer', []))
            not_after = cert.get('notAfter')
            not_before = cert.get('notBefore')
            
            ssl_info["subject"] = subject
            ssl_info["issuer"] = issuer
            ssl_info["not_before"] = not_before
            ssl_info["not_after"] = not_after
            
            if not_after:
                exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (exp_date - datetime.now(timezone.utc)).days
                ssl_info["days_until_expiration"] = days_left
                
                if days_left < 0:
                    findings.append(("CRITICAL", f"SSL Certificate has EXPIRED {abs(days_left)} days ago."))
                elif days_left < 30:
                    findings.append(("HIGH", f"SSL Certificate expires soon in {days_left} days."))
                else:
                    findings.append(("INFO", f"SSL Certificate is valid for another {days_left} days."))
                    
            if version in ["TLSv1", "TLSv1.1"]:
                findings.append(("HIGH", f"Deprecated/Insecure TLS version supported: {version}"))
            else:
                findings.append(("INFO", f"Secure TLS version active: {version}"))
                
    return ssl_info, findings

async def audit_ssl_certificate(target_url, reporter=None):
    """
    Asynchronously audits SSL/TLS certificate configuration and handshake parameters.
    """
    parsed = urlparse(target_url)
    host = parsed.hostname or parsed.path.split("/")[0]
    port = parsed.port or (443 if parsed.scheme == "https" else 443)
    
    print(f"[*] Starting SSL/TLS Certificate & Transport Security Audit against {host}:{port}")
    
    try:
        ssl_info, findings = await asyncio.to_thread(_sync_audit_ssl, host, port)
        
        print("-" * 65)
        print(f"SSL/TLS AUDIT SUMMARY")
        print("-" * 65)
        for sev, desc in findings:
            print(f"[{sev}] {desc}")
            if reporter:
                reporter.add_finding(
                    module="SSL/TLS Auditor",
                    severity=sev,
                    description=desc,
                    details=ssl_info
                )
        print("-" * 65)
        
        if reporter:
            reporter.add_section("SSL/TLS Certificate Analysis", ssl_info)
            
        print("[*] SSL/TLS audit completed successfully.")
    except Exception as e:
        error_msg = str(e)
        print(f"[-] SSL Audit Connection Error or Target Not Supporting HTTPS: {error_msg}")
        if reporter:
            reporter.add_finding(
                module="SSL/TLS Auditor",
                severity="WARNING",
                description=f"Could not perform TLS audit (Plaintext or unreachable port): {error_msg}",
                details={"error": error_msg}
            )

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://medistore.se"
    asyncio.run(audit_ssl_certificate(target))
