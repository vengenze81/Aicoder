import sys
import urllib.request
import urllib.error
import re
import ssl

def scan_target(target_url):
    print(f"\n[*] [RED TEAM RECON] Targeting: {target_url}")
    print("=" * 60)
    
    # Bypass local SSL verification warnings for lab/target testing
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AI-Coder-RedTeam/2.6'}
    
    try:
        req = urllib.request.Request(target_url, headers=headers)
        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            html_content = response.read().decode('utf-8', errors='ignore')
            resp_headers = response.headers
            status_code = response.getcode()
            
        print(f"[+] Target responded with HTTP Status: {status_code}")
        
        # 1. Header Security Audit (Offensive Perspective)
        print("\n--- [1] Security Headers Audit ---")
        security_headers = ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options']
        for header in security_headers:
            val = resp_headers.get(header)
            if val:
                print(f"  [i] {header}: {val}")
            else:
                print(f"  [-] VULNERABLE / MISSING: {header} header not set.")
                
        # 2. External Script & SRI Recon
        print("\n--- [2] Script Asset & SRI Attack Surface ---")
        script_pattern = re.compile(r'<script([^>]*?)src=["\'](https?://[^"\']+)["\']([^>]*?)></script>', re.IGNORECASE)
        matches = script_pattern.findall(html_content)
        
        if not matches:
            print("  [*] No external script tags found.")
        else:
            for prefix, url, suffix in matches:
                full_tag = f'<script{prefix}src="{url}"{suffix}></script>'
                has_integrity = 'integrity=' in prefix or 'integrity=' in suffix
                if has_integrity:
                    print(f"  [+] PROTECTED (SRI Found): {url}")
                else:
                    print(f"  [!] EXPLOITABLE (Missing SRI): {url}")
                    print(f"      -> Tag: {full_tag.strip()}")
                    
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP Error {e.code}: {e.reason}")
    except urllib.error.URLError as e:
        print(f"[-] Connection Error: {e.reason}")
    except Exception as e:
        print(f"[-] Unexpected Error: {e}")
    print("=" * 60)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 offensive_scanner.py <URL>")
        print("Example: python3 offensive_scanner.py https://medistore.se")
    else:
        scan_target(sys.argv[1])
