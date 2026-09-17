import asyncio
import httpx
import xml.etree.ElementTree as ET

async def test_xmlrpc(target_url, timeout=8.0, reporter=None):
    base = target_url.rstrip("/")
    xmlrpc_url = f"{base}/xmlrpc.php"
    print(f"[*] Probing WordPress XML-RPC endpoint at {xmlrpc_url}")
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityAuditor/1.0",
        "Content-Type": "text/xml"
    }
    
    # XML-RPC payload to request system method list
    list_methods_payload = """<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>"""

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        try:
            response = await client.post(xmlrpc_url, data=list_methods_payload, headers=headers)
            status = response.status_code
            
            if status == 200 and "<methodResponse>" in response.text:
                print(f"[+] XML-RPC endpoint is ACTIVE and responding (HTTP 200)")
                
                methods = []
                try:
                    root = ET.fromstring(response.text)
                    for val in root.findall(".//string"):
                        if val.text:
                            methods.append(val.text)
                except Exception:
                    pass
                    
                print(f"[*] Discovered {len(methods)} available XML-RPC methods.")
                
                has_pingback = any("pingback" in m.lower() for m in methods)
                has_multicall = "system.multicall" in methods
                
                print(f"    - Pingback Methods Detected (DDoS/Scan Vector): {has_pingback}")
                print(f"    - Multi-Call Enabled (Brute-Force Amplification): {has_multicall}")
                
                if reporter:
                    reporter.add_finding(
                        title="XML-RPC Endpoint Active",
                        description=f"xmlrpc.php is active with {len(methods)} methods. Pingback vectors: {has_pingback}, MultiCall: {has_multicall}",
                        severity="Medium" if has_pingback or has_multicall else "Low"
                    )
            elif status in [403, 405]:
                print(f"[-] XML-RPC endpoint is disabled, blocked, or forbidden (HTTP {status})")
                if reporter:
                    reporter.add_finding(
                        title="XML-RPC Protected / Disabled",
                        description=f"xmlrpc.php returned HTTP status {status}, indicating restriction.",
                        severity="Info"
                    )
            elif status == 404:
                print(f"[-] XML-RPC endpoint not found (HTTP 404)")
            else:
                print(f"[-] XML-RPC responded with unexpected status HTTP {status}")
                
        except Exception as e:
            print(f"[-] Error connecting to XML-RPC endpoint: {e}")
