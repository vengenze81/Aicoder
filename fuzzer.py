import argparse
from concurrent.futures import ThreadPoolExecutor
import urllib3
import requests

# Disable insecure SSL warnings for lab environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_path(target, path):
    clean_path = path.lstrip('/')
    url = f"https://{target}/{clean_path}"
    try:
        response = requests.get(url, verify=False, timeout=5)
        # Log status codes of interest
        if response.status_code in [200, 301, 302, 403, 401]:
            print(f"[+] Found: /{clean_path} (Status: {response.status_code}) -> {url}")
    except requests.RequestException:
        pass

def run_fuzzer(target, wordlist_path, threads=10):
    print(f"[*] Starting fuzzer against target: {target}")
    print(f"[*] Using wordlist: {wordlist_path}")
    
    try:
        with open(wordlist_path, 'r', encoding='utf-8') as f:
            paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"[-] Error: Wordlist file not found at {wordlist_path}")
        return

    print(f"[*] Loaded {len(paths)} paths. Spawning {threads} threads...")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for path in paths:
            executor.submit(check_path, target, path)
            
    print("[*] Fuzzing complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-threaded directory fuzzer for lab testing")
    parser.add_argument("--target", required=True, help="Target domain or IP address (e.g., 10.10.x.x)")
    parser.add_argument("--wordlist", required=True, help="Path to your wordlist file")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")
    
    args = parser.parse_args()
    run_fuzzer(args.target, args.wordlist, args.threads)

