import asyncio
import re
from urllib.parse import urljoin, urlparse
import httpx
from bs4 import BeautifulSoup

# Comprehensive regex patterns for sensitive keys and hidden endpoints
SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Bearer Token": re.compile(r"bearer\s+[a-zA-Z0-9_\-\.]{20,}", re.IGNORECASE),
    "Generic API Key": re.compile(r"api[_-]?key['\" ]*[:=]['\" ]*([a-zA-Z0-9_\-]{16,45})", re.IGNORECASE),
    "Authorization Header": re.compile(r"authorization['\" ]*[:=]['\" ]*([a-zA-Z0-9_\-\.]{15,})", re.IGNORECASE),
    "Private Key": re.compile(r"-----BEGIN (?:RSA|PRIVATE) KEY-----"),
    "JWT Token": re.compile(r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+")
}

ENDPOINT_PATTERN = re.compile(r"['\"](\/[a-zA-Z0-9_\-\/]+(?:\?[a-zA-Z0-9_\-\&=]*)?)['\"]")

async def extract_javascript_assets(target_url, reporter=None):
    """
    Crawls target HTML, extracts all linked JS scripts, downloads them asynchronously,
    and hunts for hardcoded secrets, tokens, and hidden endpoints.
    """
    print(f"[*] Starting JavaScript Secret & Endpoint Extraction against {target_url}")
    
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityAuditor/2.0"}
    
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
            response = await client.get(target_url, headers=headers)
            if response.status_code != 200:
                print(f"[-] Failed to fetch target page. HTTP Status: {response.status_code}")
                return

            soup = BeautifulSoup(response.text, "html.parser")
            script_tags = soup.find_all("script", src=True)
            
            script_urls = set()
            for tag in script_tags:
                src = tag.get("src")
                if src:
                    full_url = urljoin(target_url, src)
                    # Only analyze scripts belonging to the same domain or relative assets
                    if urlparse(full_url).netloc == urlparse(target_url).netloc:
                        script_urls.add(full_url)

            print(f"[*] Discovered {len(script_urls)} local JavaScript bundles. Analyzing content...")
            
            all_secrets_found = []
            all_endpoints_found = set()

            async def fetch_and_analyze(script_url):
                try:
                    res = await client.get(script_url, headers=headers)
                    if res.status_code == 200:
                        content = res.text
                        
                        # Scan for secrets
                        for secret_type, pattern in SECRET_PATTERNS.items():
                            matches = pattern.findall(content)
                            for match in matches:
                                snippet = match if isinstance(match, str) else match[0]
                                all_secrets_found.append({"type": secret_type, "source": script_url, "match": snippet[:10] + "..."})
                        
                        # Scan for endpoints
                        ep_matches = ENDPOINT_PATTERN.findall(content)
                        for ep in ep_matches:
                            if len(ep) > 3 and not ep.endswith(('.js', '.css', '.png', '.jpg', '.woff')):
                                all_endpoints_found.add(ep)
                except Exception:
                    pass

            # Concurrently fetch and analyze all JavaScript files
            await asyncio.gather(*(fetch_and_analyze(url) for url in script_urls))

            # Display Results
            print("-" * 65)
            print(f"JAVASCRIPT SECURITY FINDINGS SUMMARY")
            print("-" * 65)
            print(f"[*] Total Secrets/Tokens Flagged: {len(all_secrets_found)}")
            print(f"[*] Total Unique Endpoints Discovered: {len(all_endpoints_found)}")
            print("-" * 65)

            if all_secrets_found:
                print("\n[!] Potential Secrets Detected:")
                for s in all_secrets_found[:10]: # Print top 10
                    print(f"    - Type: {s['type']} | Source: {s['source']} | Preview: {s['match']}")
            else:
                print("[+] No high-risk hardcoded secrets or API keys identified in JS bundles.")

            if reporter:
                reporter.add_section("JavaScript Asset Analysis", {
                    "scripts_analyzed": len(script_urls),
                    "secrets_found": all_secrets_found,
                    "endpoints_discovered": list(all_endpoints_found)[:50]
                })

            print(f"[*] JavaScript extraction audit completed successfully.")

    except Exception as e:
        print(f"[-] Error during JavaScript extraction: {e}")

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://medistore.se"
    asyncio.run(extract_javascript_assets(target))
