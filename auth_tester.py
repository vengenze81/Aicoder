import asyncio
import httpx

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
        "Referer": login_url
    }
    
    try:
        kwargs = {"headers": headers, "timeout": timeout, "follow_redirects": False}
        if proxy:
            kwargs["proxy"] = proxy
            
        async with httpx.AsyncClient() as client:
            response = await client.post(login_url, data=payload, **kwargs)
            
            # Successful WP login responds with a 302 redirect and sets the logged-in cookie
            set_cookie_header = response.headers.get("set-cookie", "")
            is_redirect = response.status_code == 302
            has_auth_cookie = "wordpress_logged_in_" in set_cookie_header
            
            if is_redirect and has_auth_cookie:
                return True, "SUCCESS: Valid credentials verified (Auth Cookie Issued)"
            elif "incorrect" in response.text.lower() or "invalid" in response.text.lower():
                return False, "Failed: Invalid username or password"
            else:
                return False, f"Blocked/Protected (HTTP Status: {response.status_code})"
                
    except (httpx.RequestError, asyncio.TimeoutError) as e:
        return False, f"Connection Error: {e}"

async def run_credential_audit(target_url, username_file, password, timeout=8.0):
    try:
        with open(username_file, "r", encoding="utf-8") as f:
            usernames = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"[-] Username file not found: {username_file}")
        return

    print(f"[*] Starting Credential Audit against {target_url}/wp-login.php")
    print(f"[*] Testing {len(usernames)} user handles with provided password credential...\n")

    for uname in usernames:
        print(f"[*] Testing user: '{uname}' ... ", end="", flush=True)
        success, message = await test_wordpress_login(target_url, uname, password, timeout=timeout)
        if success:
            print(f"\n    🚨 [VALID CREDENTIAL FOUND!] Username: {uname} | Password: {password}")
        else:
            print(f"[{message}]")
        await asyncio.sleep(1.5) # Polite delay to evade rate limits
