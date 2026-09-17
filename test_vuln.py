import asyncio
import httpx
import sys

TARGET_ENDPOINTS = [
    ("/wp-json/code-snippets/v1/snippets", "Code Snippets Plugin API"),
    ("/wp-json/code-snippets/v1/snippets/1", "Code Snippet ID #1 Probe"),
    ("/wp-json/sharespine/v1/", "Sharespine Integration Root"),
    ("/wp-json/wc/store/v1/cart", "WooCommerce Store Cart API"),
    ("/wp-json/wc/store/v1/products/search", "WooCommerce Product Search API"),
    ("/wp-json/wp/v2/users", "WordPress User Enumeration Endpoint")
]

async def test_endpoint(client, base_url, path, description):
    url = base_url.rstrip("/") + path
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json"
    }
    
    try:
        response = await client.get(url, headers=headers, timeout=10.0, follow_redirects=True)
        print(f"[*] Testing [{description}] -> {path}")
        print(f"    └── Status: HTTP {response.status_code} | Size: {len(response.content)} bytes")
        
        if response.status_code == 200:
            content_type = response.headers.get("content-type", "")
            if "application/json" in content_type:
                print(f"    └── [!] VULN/EXPOSURE: Unauthenticated JSON data returned!")
                try:
                    data = response.json()
                    print(f"    └── Snippet/Data Preview: {str(data)[:200]}...")
                except Exception:
                    print(f"    └── Raw text: {response.text[:150]}...")
            else:
                print(f"    └── Response is HTML/Text (Size: {len(response.text)})")
        elif response.status_code == 401:
            print(f"    └── [Secure] Endpoint properly enforces Authentication (HTTP 401)")
        elif response.status_code == 403:
            print(f"    └── [Secure] Access Forbidden (HTTP 403)")
        else:
            print(f"    └── Response code {response.status_code}")
        print("-" * 60)
        
    except Exception as e:
        print(f"[-] Error probing {path}: {e}")

async def run_tests(target):
    async with httpx.AsyncClient() as client:
        print(f"[*] Starting Targeted Vulnerability Probes against: {target}\n" + "="*60)
        for path, desc in TARGET_ENDPOINTS:
            await test_endpoint(client, target, path, desc)
            await asyncio.sleep(0.5)

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://medistore.se"
    asyncio.run(run_tests(target))
