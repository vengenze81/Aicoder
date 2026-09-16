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

def test_basic_auth(session, target_url, path, username, password, verbose=False):
    """Tests HTTP Basic Authentication."""
    url = f"{target_url.rstrip('/')}{path}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    
    try:
        baseline = session.get(url, headers=headers, timeout=5, allow_redirects=True, verify=False)
        if baseline.status_code == 404:
            return None

        auth_challenged = (baseline.status_code == 401 or 'WWW-Authenticate' in baseline.headers)
        if not auth_challenged:
            return None

        resp = session.get(url, auth=HTTPBasicAuth(username, password), headers=headers, timeout=5, allow_redirects=True, verify=False)
        if resp.status_code in [200, 204, 302] and resp.status_code != 401:
            return {
                "username": username,
                "password": password,
                "endpoint": url,
                "type": "basic",
                "status_code": resp.status_code
            }
    except requests.exceptions.RequestException:
        pass
    return None

def test_form_auth(session, target_url, username, password, user_field, pass_field, failure_keyword, verbose=False):
    """Tests HTML Form-Based (POST) Authentication."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    payload = {
        user_field: username,
        pass_field: password
    }

    try:
        resp = session.post(
            target_url,
            data=payload,
            headers=headers,
            timeout=5,
            allow_redirects=True,
            verify=False
        )

        # Determine success: Check if response code indicates redirection/success
        # AND the failure keyword is NOT present in the response body.
        is_success = False
        if resp.status_code in [200, 302, 303]:
            body_text = resp.text.lower()
            if failure_keyword and failure_keyword.lower() not in body_text:
                is_success = True
            elif not failure_keyword and resp.status_code == 302:
                is_success = True

        if is_success:
            return {
                "username": username,
                "password": password,
                "endpoint": target_url,
                "type": "form",
                "status_code": resp.status_code
            }
        elif verbose:
            print(f"[-] Failed form login {username}:{password} at {target_url} (Status: {resp.status_code})")

    except requests.exceptions.RequestException as e:
        if verbose:
            print(f"[!] Request exception for {target_url}: {e}")
        pass

    return None

def run_analysis(args):
    usernames = load_wordlist(args.users)
    passwords = load_wordlist(args.passwords)
    paths = load_wordlist(args.paths) if args.paths else []

    if not usernames:
        usernames = ["admin", "root", "user"]
    if not passwords:
        passwords = ["password", "123456", "admin"]

    print(f"[*] Loaded {len(usernames)} username(s) and {len(passwords)} password(s).")
    print(f"[*] Auth Type: {args.auth_type.upper()}")
    print(f"[*] Running with max {args.threads} concurrent threads...\n" + "-" * 60)

    valid_credentials = []
    session = requests.Session()
    if args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}

    tasks = []
    if args.auth_type == "basic":
        if not paths:
            paths = ["/", "/login", "/admin", "/api", "/secure"]
        for user in usernames:
            for pwd in passwords:
                for path in paths:
                    tasks.append(('basic', user, pwd, path))
    else:
        for user in usernames:
            for pwd in passwords:
                tasks.append(('form', user, pwd, args.url))

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for task in tasks:
            if task[0] == 'basic':
                futures.append(executor.submit(test_basic_auth, session, args.url, task[3], task[1], task[2], args.verbose))
            else:
                futures.append(executor.submit(test_form_auth, session, args.url, task[1], task[2], args.user_field, args.pass_field, args.failure_keyword, args.verbose))

        for future in as_completed(futures):
            result = future.result()
            if result:
                valid_credentials.append(result)
                print(f"\n[+] [SUCCESS] Valid login found -> {result['username']}:{result['password']} at {result['endpoint']} (Type: {result['type']})\n")

    return valid_credentials

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Security Analyzer for Basic & Form-Based Authentication")
    parser.add_argument("-u", "--url", required=True, help="Target URL (Base URL for basic auth, or full login POST URL for form auth)")
    parser.add_argument("--auth-type", choices=["basic", "form"], default="basic", help="Authentication type to test")
    parser.add_argument("--users", default="usernames.txt", help="Path to usernames wordlist")
    parser.add_argument("--passwords", default="passwords.txt", help="Path to passwords wordlist")
    parser.add_argument("--paths", help="Path to endpoints wordlist (Basic Auth only)")
    parser.add_argument("--user-field", default="username", help="Form field name for username (Form Auth only)")
    parser.add_argument("--pass-field", default="password", help="Form field name for password (Form Auth only)")
    parser.add_argument("--failure-keyword", default="invalid", help="Keyword in response body indicating login failure (Form Auth only)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("--proxy", help="Route traffic through a proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug output")
    parser.add_argument("-o", "--output", help="Save results to a JSON file")

    args = parser.parse_args()

    print(f"[*] Starting Auth analysis on: {args.url}")
    start_time = datetime.now()
    
    found = run_analysis(args)

    duration = datetime.now() - start_time
    print(f"\n[+] Scan Complete in {duration.total_seconds():.2f}s. Total valid credentials found: {len(found)}")

    if args.output and found:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(found, f, indent=4)
        print(f"[*] Results successfully exported to {args.output}")
