import asyncio
import socket
from urllib.parse import urlparse

# Common high-value ports for web and infrastructure reconnaissance
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Dev"
}

async def scan_single_port(host, port, service_name, timeout=3.0):
    """
    Asynchronously attempts a TCP connection to a given port and grabs banners if available.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), 
            timeout=timeout
        )
        
        banner = ""
        try:
            # Try to read initial banner data if the service talks first (e.g., SSH, FTP)
            writer.set_write_buffer_limits(high_water=2048)
            data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
            banner = data.decode("utf-8", errors="ignore").strip()
        except Exception:
            pass

        writer.close()
        await writer.wait_closed()
        return {"port": port, "service": service_name, "status": "OPEN", "banner": banner}
    except Exception:
        return None

async def scan_ports(target_url, reporter=None):
    """
    Scans a list of common ports asynchronously against the target host.
    """
    parsed = urlparse(target_url)
    netloc = parsed.netloc or parsed.path
    host = netloc.split(":")[0] # Strip port if present in URL

    print(f"[*] Starting Async Port & Service Banner Scan against host: {host}")
    print(f"[*] Probing {len(COMMON_PORTS)} common infrastructure and web ports...")

    tasks = [scan_single_port(host, port, service) for port, service in COMMON_PORTS.items()]
    results = await asyncio.gather(*tasks)
    
    open_ports = [r for r in results if r is not None]

    print("-" * 65)
    print(f"PORT SCANNER SECURITY FINDINGS SUMMARY")
    print("-" * 65)
    print(f"[*] Total Open Ports Discovered: {len(open_ports)}")
    print("-" * 65)

    if open_ports:
        print(f"{'PORT':<8} | {'SERVICE':<12} | {'STATUS':<8} | {'BANNER / DETAILS'}")
        print("-" * 65)
        for p in open_ports:
            banner_snippet = p['banner'][:30] if p['banner'] else "N/A"
            print(f"{p['port']:<8} | {p['service']:<12} | {p['status']:<8} | {banner_snippet}")
            
            if reporter:
                reporter.add_finding(
                    module="Port Scanner",
                    severity="INFO",
                    description=f"Open port discovered: {p['port']} ({p['service']})",
                    details={"port": p['port'], "service": p['service'], "banner": p['banner']}
                )
    else:
        print("[+] No target ports responded or ports are firewalled.")

    if reporter:
        reporter.add_section("Port Scanner Analysis", {
            "target_host": host,
            "open_ports": open_ports
        })

    print(f"[*] Port scan completed successfully.")

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://medistore.se"
    asyncio.run(scan_ports(target))
