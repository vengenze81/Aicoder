import asyncio
import httpx
import sys

async def probe_xmlrpc(target_url):
    url = target_url.rstrip("/") + "/xmlrpc.php"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Content-Type": "text/xml"
    }
    
    # XML-RPC payload to list available methods (checks if service is active)
    payload = """<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>"""
    
    print(f"[*] Probing XML-RPC endpoint: {url}")
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(url, headers=headers, content=payload, timeout=10.0, follow_redirects=True)
            print(f"    └── Status: HTTP {response.status_code} | Size: {len(response.content)} bytes")
            
            if response.status_code == 200 and "methodResponse" in response.text:
                print("    └── [!] EXPOSURE FOUND: XML-RPC is ACTIVE and responding to method calls!")
                print(f"    └── Response Preview: {response.text[:300]}...")
                if "system.multicall" in response.text:
                    print("    └── [!] CRITICAL: 'system.multicall' is enabled (Vulnerable to brute-force amplification).")
            elif response.status_code == 403:
                print("    └── [Secure] XML-RPC is actively blocked or forbidden (HTTP 403)")
            else:
                print(f"    └── Response text preview: {response.text[:150]}")
        except Exception as e:
            print(f"[-] Error probing XML-RPC: {e}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://medistore.se"
    asyncio.run(probe_xmlrpc(target))
