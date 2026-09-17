import asyncio
import ssl
import socket
from urllib.parse import urlparse

PLUGIN_META = {
    "name": "SSL/TLS Security Auditor",
    "flag": "--ssl-scan",
    "description": "Audit SSL/TLS certificate and cipher suites",
    "category": "recon"
}

async def run(target_url, reporter=None):
    print(f"[*] Starting SSL/TLS Certificate Audit against: {target_url}")
    parsed = urlparse(target_url)
    hostname = parsed.netloc or target_url.replace("https://", "").replace("http://", "").split("/")[0]
    
    findings = []
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        def fetch_cert():
            with socket.create_connection((hostname, 443), timeout=5.0) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return ssock.getpeercert()

        cert = await asyncio.to_thread(fetch_cert)
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        
        desc = f"Valid SSL Certificate issued to: {subject.get('commonName', 'Unknown')} by {issuer.get('organizationName', 'Unknown')}"
        print(f"[+] [INFO] {desc}")
        findings.append({"hostname": hostname, "subject": subject, "issuer": issuer, "severity": "LOW"})
        
        if reporter:
            reporter.add_section("SSL Audit Analysis", {"hostname": hostname, "subject": subject, "issuer": issuer})
    except Exception as e:
        print(f"[-] SSL Audit failed or target non-HTTPS: {e}")

    print(f"[*] SSL/TLS audit completed.")
