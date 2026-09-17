import sys
import asyncio
from engine import run_stealth_scanner
from config import PROXY_LIST

def load_wordlist(filepath):
    endpoints = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith('#'):
                    if not line.startswith('/'):
                        line = '/' + line
                    endpoints.append(line)
    except FileNotFoundError:
        print(f"[-] Wordlist file not found: {filepath}. Falling back to default baseline paths.")
        endpoints = ["/", "/robots.txt", "/sitemap.xml", "/wp-login.php", "/cart"]
    return endpoints

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://medistore.se"
    wordlist_path = sys.argv[2] if len(sys.argv) > 2 else "wordlist.txt"
    
    test_endpoints = load_wordlist(wordlist_path)
    
    proxy_status = f"{len(PROXY_LIST)} proxies loaded" if PROXY_LIST else "Direct mode (No proxies configured)"
    print(f"[*] Initializing Modular Stealth Engine")
    print(f"[*] Target Domain: {target}")
    print(f"[*] Wordlist File: {wordlist_path} ({len(test_endpoints)} paths loaded)")
    print(f"[*] Network Pool: {proxy_status}\n")
    
    asyncio.run(run_stealth_scanner(target, test_endpoints))
