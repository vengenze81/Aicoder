import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
import urllib3
import os
import argparse
import json
import re
import threading
import itertools
import time
import random
import base64
import hmac
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from collections import Counter, defaultdict

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

# Suppress insecure request warnings if testing self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CircuitBreaker:
    """Thread-safe circuit breaker to halt scanning upon hitting account lockouts or WAF rate limits."""
    def __init__(self, threshold=3):
        self.threshold = threshold
        self.lockout_count = 0
        self.tripped = False
        self.lock = threading.Lock()

    def record_lockout(self):
        with self.lock:
            self.lockout_count += 1
            if self.lockout_count >= self.threshold:
                self.tripped = True

    def is_tripped(self):
        with self.lock:
            return self.tripped

class ProxyPool:
    """Thread-safe round-robin proxy pool manager."""
    def __init__(self, filepath=None):
        self.proxies = []
        if filepath and os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                self.proxies = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        self.lock = threading.Lock()
        self.cycle = itertools.cycle(self.proxies) if self.proxies else None

    def get_proxy_dict(self):
        if not self.cycle:
            return None
        with self.lock:
            p = next(self.cycle)
            return {"http": p, "https": p}

def load_wordlist(filepath):
    """Loads lines from a file into a list, ignoring empty lines and comments."""
    if not filepath or not os.path.exists(filepath):
        return []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

def mutate_passwords(passwords):
    """Applies smart password mutation rules (capitalization, years, leetspeak, symbols)."""
    mutated = set(passwords)
    suffixes = ["2025", "2026", "2027", "123", "1234", "!", "@", "#", "!@#"]
    
    for pwd in passwords:
        mutated.add(pwd.capitalize())
        mutated.add(pwd.upper())
        mutated.add(pwd.lower())
        
        for s in suffixes:
            mutated.add(f"{pwd}{s}")
            mutated.add(f"{pwd.capitalize()}{s}")
            
        leet = pwd.replace('e', '3').replace('a', '@').replace('s', '$').replace('o', '0')
        mutated.add(leet)
        mutated.add(leet.capitalize())
        for s in suffixes:
            mutated.add(f"{leet}{s}")
            
    return list(mutated)

def apply_jitter(delay):
    """Applies a random jitter delay to mimic human behavior and evade WAF throttling."""
    if delay > 0:
        actual_delay = delay + random.uniform(0, delay * 0.5)
        time.sleep(actual_delay)

def check_lockout(resp_text, status_code, lockout_keyword):
    """Checks if a response indicates account lockout or rate limiting."""
    if status_code == 429:
        return True
    if lockout_keyword and lockout_keyword.lower() in resp_text.lower():
        return True
    return False

def get_request_proxies(proxy_pool, single_proxy):
    """Determines proxies to use for a specific request."""
    if proxy_pool and proxy_pool.proxies:
        return proxy_pool.get_proxy_dict()
    elif single_proxy:
        return {"http": single_proxy, "https": single_proxy}
    return None

def parse_custom_headers(header_args):
    """Parses custom header strings into a dictionary."""
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    if header_args:
        for h in header_args:
            if ":" in h:
                key, val = h.split(":", 1)
                headers[key.strip()] = val.strip()
    return headers

def parse_cookies(cookie_arg):
    """Parses a cookie string into a dictionary."""
    cookies = {}
    if cookie_arg:
        for item in cookie_arg.split(";"):
            if "=" in item:
                k, v = item.split("=", 1)
                cookies[k.strip()] = v.strip()
    return cookies

def extract_csrf_token(html_content, csrf_field_name):
    """Extracts a dynamic CSRF token from HTML using BeautifulSoup or regex fallback."""
    token = None
    if BS4_AVAILABLE:
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            inp = soup.find('input', {'name': csrf_field_name})
            if inp and inp.get('value'):
                return inp.get('value')
            
            meta = soup.find('meta', {'name': csrf_field_name})
            if meta and meta.get('content'):
                return meta.get('content')
            
            for tag in soup.find_all('input', {'name': re.compile(r'csrf|token', re.I)}):
                if tag.get('value'):
                    return tag.get('value')
        except Exception:
            pass

    pattern = rf'<input[^>]+name=["\']?{csrf_field_name}["\']?[^>]+value=["\']?([^"\']+)["\']?'
    match = re.search(pattern, html_content, re.IGNORECASE)
    if match:
        token = match.group(1)
    else:
        generic_match = re.search(r'<input[^>]+value=["\']?([^"\']+)["\']?[^>]+name=["\']?.*?(?:csrf|token).*?["\']?', html_content, re.IGNORECASE)
        if generic_match:
            token = generic_match.group(1)
            
    return token

def base64_url_decode(inp):
    """Decodes base64url encoded strings safely with proper padding."""
    rem = len(inp) % 4
    if rem > 0:
        inp += '=' * (4 - rem)
    return base64.urlsafe_b64decode(inp.encode('utf-8'))

def audit_jwt_token(token, secret_file):
    """Decodes a JWT, analyzes claims and algorithm security, and attempts offline weak secret cracking."""
    print("\n" + "="*60 + "\n[*] Starting Automated JWT Security Audit:")
    parts = token.split('.')
    if len(parts) != 3:
        print("    [-] Provided token is not a valid 3-part JWT structure.")
        print("="*60)
        return None

    try:
        header_json = json.loads(base64_url_decode(parts[0]).decode('utf-8'))
        payload_json = json.loads(base64_url_decode(parts[1]).decode('utf-8'))
    except Exception as e:
        print(f"    [-] Failed to decode JWT header/payload: {e}")
        print("="*60)
        return None

    print(f"    - Algorithm (alg): {header_json.get('alg', 'UNKNOWN')}")
    print(f"    - Token Type (typ): {header_json.get('typ', 'N/A')}")
    print(f"    - Decoded Payload Claims: {json.dumps(payload_json, indent=8)}")

    vulnerabilities = []
    alg = header_json.get('alg', '').lower()

    if alg == 'none':
        print("\n    [!] [CRITICAL VULNERABILITY] JWT uses 'none' algorithm (Signature Bypass possible)!")
        vulnerabilities.append("Insecure 'none' algorithm")
    elif alg.startswith('hs'):
        print(f"\n    [*] JWT uses HMAC signature ({alg.upper()}). Attempting offline secret brute-force...")
        secrets = load_wordlist(secret_file)
        if not secrets:
            secrets = ["secret", "password", "123456", "admin", "supersecret", "key", "jwt_secret", "secretkey"]
            print(f"    - No secret file found at '{secret_file}'. Using default weak secret wordlist ({len(secrets)} items).")
        else:
            print(f"    - Loaded {len(secrets)} candidate secret(s) from {secret_file}.")

        message = f"{parts[0]}.{parts[1]}".encode('utf-8')
        target_sig_b64 = parts[2]
        cracked_secret = None

        for sec in secrets:
            hasher = hmac.new(sec.encode('utf-8'), message, hashlib.sha256 if alg == 'hs256' else hashlib.sha512)
            computed_sig = base64.urlsafe_b64encode(hasher.digest()).decode('utf-8').rstrip('=')
            if hmac.compare_digest(computed_sig, target_sig_b64):
                cracked_secret = sec
                break

        if cracked_secret:
            print(f"    [+] [CRITICAL VULNERABILITY] Weak JWT Secret Cracked Successfully -> '{cracked_secret}'")
            vulnerabilities.append(f"Weak HS256 secret cracked: '{cracked_secret}'")
        else:
            print("    [-] No matching secret found in wordlist.")

    exp = payload_json.get('exp')
    if exp:
        exp_dt = datetime.fromtimestamp(exp)
        is_expired = datetime.now() > exp_dt
        print(f"    - Expiration (exp): {exp_dt} ({'Expired' if is_expired else 'Active'})")
        if not is_expired and exp - time.time() > 86400 * 30:
            print("    [!] [WARNING] Token has an exceptionally long lifespan.")

    print("="*60)
    return {
        "header": header_json,
        "payload": payload_json,
        "vulnerabilities": vulnerabilities
    }

def audit_mfa_flow(session, mfa_url, otp_field, test_codes, proxy_pool, single_proxy, base_headers, cookies):
    """Audits secondary MFA/OTP verification endpoints for bypass flaws or valid code reuse."""
    print("\n" + "="*60 + "\n[*] Starting Multi-Factor Authentication (MFA) Flow Audit:")
    print(f"    - Target MFA Endpoint: {mfa_url}")
    print(f"    - Testing {len(test_codes)} candidate OTP code(s)...")

    req_proxies = get_request_proxies(proxy_pool, single_proxy)
    mfa_findings = []

    for code in test_codes:
        headers = base_headers.copy()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        payload = {otp_field: code}
        
        try:
            resp = session.post(mfa_url, data=payload, headers=headers, cookies=cookies, proxies=req_proxies, timeout=5, allow_redirects=True, verify=False)
            if resp.status_code in [200, 302, 303]:
                # Check if submission succeeded (did not return to MFA prompt or error)
                if "invalid" not in resp.text.lower() and "error" not in resp.text.lower() and "code" not in resp.text.lower():
                    print(f"    [+] [MFA BYPASS / SUCCESS] Valid access achieved using OTP code: '{code}' (Status: {resp.status_code})")
                    mfa_findings.append({"code": code, "status_code": resp.status_code})
                    break
                else:
                    print(f"    [-] Tested OTP '{code}' -> Rejected")
        except requests.exceptions.RequestException as e:
            print(f"    [!] Request error during MFA test with code {code}: {e}")

    if not mfa_findings:
        print("    [+] MFA endpoint properly rejected all test codes.")
    print("="*60)
    return mfa_findings

def test_user_existence(session, target_url, username, auth_type, content_type, user_field, pass_field, proxy_pool, single_proxy, base_headers, cookies, extract_csrf, csrf_field, probe_password, delay, verbose):
    """Probes a single username with a dummy password to check for account existence via differential response analysis."""
    headers = base_headers.copy()
    req_proxies = get_request_proxies(proxy_pool, single_proxy)
    apply_jitter(delay)

    start_time = time.time()
    try:
        if auth_type == "form":
            hidden_inputs = {}
            csrf_token = None

            get_resp = session.get(target_url, headers=headers, cookies=cookies, proxies=req_proxies, timeout=5, allow_redirects=True, verify=False)
            if get_resp.status_code == 200:
                if extract_csrf:
                    csrf_token = extract_csrf_token(get_resp.text, csrf_field)
                matches = re.findall(r'<input[^>]+type=["\']?hidden["\']?[^>]*>', get_resp.text, re.IGNORECASE)
                for m in matches:
                    name_match = re.search(r'name=["\']?([^"\']+)["\']?', m, re.IGNORECASE)
                    val_match = re.search(r'value=["\']?([^"\']*)["\']?', m, re.IGNORECASE)
                    if name_match:
                        hidden_inputs[name_match.group(1)] = val_match.group(1) if val_match else ""

            if csrf_token:
                hidden_inputs[csrf_field] = csrf_token

            if content_type == "json":
                headers["Content-Type"] = "application/json"
                payload = json.dumps({user_field: username, pass_field: probe_password, **hidden_inputs})
                resp = session.post(target_url, data=payload, headers=headers, cookies=cookies, proxies=req_proxies, timeout=5, allow_redirects=True, verify=False)
            else:
                if "Content-Type" not in headers:
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
                payload = {user_field: username, pass_field: probe_password, **hidden_inputs}
                resp = session.post(target_url, data=payload, headers=headers, cookies=cookies, proxies=req_proxies, timeout=5, allow_redirects=True, verify=False)

            elapsed = time.time() - start_time
            return {
                "username": username,
                "status_code": resp.status_code if resp else 0,
                "response_length": len(resp.content) if resp else 0,
                "response_text": resp.text if resp else "",
                "response_time": elapsed
            }
    except requests.exceptions.RequestException as e:
        if verbose:
            print(f"[!] Enum request exception for user {username}: {e}")
    return None

def run_user_enumeration(session, target_url, usernames, auth_type, content_type, user_field, pass_field, proxy_pool, single_proxy, base_headers, cookies, extract_csrf, csrf_field, probe_password, delay, threads, verbose):
    """Runs differential user enumeration across all usernames in the wordlist."""
    print("\n" + "="*60 + "\n[*] Starting Dedicated Account Enumeration Phase:")
    print(f"    - Probing {len(usernames)} username(s) with dummy password...")

    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(
                test_user_existence, session, target_url, user, auth_type, content_type,
                user_field, pass_field, proxy_pool, single_proxy, base_headers, cookies,
                extract_csrf, csrf_field, probe_password, delay, verbose
            )
            for user in usernames
        ]
        for f in as_completed(futures):
            res = f.result()
            if res:
                results.append(res)

    if not results:
        print("    [-] User enumeration returned no results.")
        print("="*60)
        return []

    lengths = [r['response_length'] for r in results]
    length_counts = Counter(lengths)
    baseline_length, baseline_count = length_counts.most_common(1)[0]

    valid_users = []
    print(f"    - Baseline Failure Response Length: {baseline_length} bytes ({baseline_count} occurrences)")

    for r in results:
        l = r['response_length']
        if l != baseline_length:
            diff = abs(l - baseline_length)
            print(f"    [+] [POTENTIAL VALID USER] '{r['username']}' -> Length: {l}B (Diff: {diff:+d}B, Status: {r['status_code']})")
            valid_users.append(r['username'])
        elif verbose:
            print(f"    [-] Checked '{r['username']}' -> Length: {l}B (Matches baseline)")

    if not valid_users:
        print("    [+] All usernames produced identical responses (strong anti-enumeration defenses).")
    else:
        print(f"\n[+] Enumeration Complete. Discovered {len(valid_users)} potential valid account(s).")
    print("="*60)
    return valid_users

def test_auth(session, target_url, username, password, auth_type, content_type, user_field, pass_field, failure_keyword, success_regex, proxy_pool, single_proxy, base_headers, cookies, circuit_breaker, extract_csrf=False, csrf_field="csrf_token", delay=0, lockout_keyword=None, verbose=False):
    """Handles authentication testing with optional dynamic CSRF token extraction and circuit breaker protection."""
    if circuit_breaker.is_tripped():
        return None

    headers = base_headers.copy()
    req_proxies = get_request_proxies(proxy_pool, single_proxy)
    apply_jitter(delay)

    start_time = time.time()
    resp = None
    is_success = False

    try:
        if auth_type == "form":
            hidden_inputs = {}
            csrf_token = None

            get_resp = session.get(target_url, headers=headers, cookies=cookies, proxies=req_proxies, timeout=5, allow_redirects=True, verify=False)
            
            if get_resp.status_code == 200:
                if extract_csrf:
                    csrf_token = extract_csrf_token(get_resp.text, csrf_field)

                matches = re.findall(r'<input[^>]+type=["\']?hidden["\']?[^>]*>', get_resp.text, re.IGNORECASE)
                for m in matches:
                    name_match = re.search(r'name=["\']?([^"\']+)["\']?', m, re.IGNORECASE)
                    val_match = re.search(r'value=["\']?([^"\']*)["\']?', m, re.IGNORECASE)
                    if name_match:
                        hidden_inputs[name_match.group(1)] = val_match.group(1) if val_match else ""

            if csrf_token:
                hidden_inputs[csrf_field] = csrf_token

            if content_type == "json":
                headers["Content-Type"] = "application/json"
                payload = json.dumps({user_field: username, pass_field: password, **hidden_inputs})
                resp = session.post(target_url, data=payload, headers=headers, cookies=cookies, proxies=req_proxies, timeout=5, allow_redirects=True, verify=False)
            else:
                if "Content-Type" not in headers:
                    headers["Content-Type"] = "application/x-www-form-urlencoded"

                payload = {user_field: username, pass_field: password, **hidden_inputs}
                apply_jitter(delay)
                resp = session.post(
                    target_url, data=payload, headers=headers, cookies=cookies,
                    proxies=req_proxies, timeout=5, allow_redirects=True, verify=False
                )

            if resp.status_code in [200, 201, 302, 303]:
                body_text = resp.text
                if success_regex and re.search(success_regex, body_text):
                    is_success = True
                elif failure_keyword and failure_keyword.lower() not in body_text.lower():
                    is_success = True
                elif not failure_keyword and resp.status_code in [200, 201, 302]:
                    is_success = True

        elif auth_type == "basic":
            auth = HTTPBasicAuth(username, password)
            resp = session.get(target_url, auth=auth, headers=headers, cookies=cookies, proxies=req_proxies, timeout=5, verify=False)
            if resp.status_code == 200:
                if not success_regex or re.search(success_regex, resp.text):
                    is_success = True

        elif auth_type == "digest":
            auth = HTTPDigestAuth(username, password)
            resp = session.get(target_url, auth=auth, headers=headers, cookies=cookies, proxies=req_proxies, timeout=5, verify=False)
            if resp.status_code == 200:
                if not success_regex or re.search(success_regex, resp.text):
                    is_success = True

        elapsed = time.time() - start_time
        resp_length = len(resp.content) if resp else 0
        status_code = resp.status_code if resp else 0

        if resp and check_lockout(resp.text, status_code, lockout_keyword):
            circuit_breaker.record_lockout()
            print(f"[!] [CIRCUIT BREAKER WARNING] Lockout/Rate-limit triggered for user '{username}' at {target_url} (Status: {status_code})")

        captured_cookies = {c.name: c.value for c in resp.cookies} if resp else {}
        captured_headers = {k: v for k, v in resp.headers.items() if 'auth' in k.lower() or 'token' in k.lower() or 'set-cookie' in k.lower()} if resp else {}
        jwt_candidates = re.findall(r'ey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', resp.text) if resp else []

        # Check if response indicates MFA challenge trigger
        is_mfa_challenge = False
        if resp and any(keyword in resp.text.lower() for keyword in ["mfa", "otp", "two-factor", "authenticator code", "verification code"]):
            is_mfa_challenge = True

        result = {
            "username": username,
            "password": password,
            "endpoint": target_url,
            "type": auth_type,
            "status_code": status_code,
            "response_time": elapsed,
            "response_length": resp_length,
            "success": is_success,
            "is_mfa_challenge": is_mfa_challenge,
            "session_cookies": captured_cookies,
            "session_headers": captured_headers,
            "jwt_candidates": jwt_candidates
        }

        if is_success:
            if is_mfa_challenge:
                print(f"\n[+] [MFA CHALLENGE] Valid login found ({username}:{password}), but MFA verification required at {target_url}")
            else:
                print(f"\n[+] [SUCCESS] Valid login found -> {username}:{password} at {target_url} [{auth_type.upper()}]")
            if captured_cookies:
                print(f"    [+] Harvested Cookies: {captured_cookies}")
            if captured_headers:
                print(f"    [+] Harvested Auth Headers: {captured_headers}")
            if jwt_candidates:
                print(f"    [+] Discovered JWT Tokens in Response: {len(jwt_candidates)} token(s)\n")
        elif verbose:
            print(f"[-] Failed {auth_type} login {username}:{password} at {target_url} (Status: {status_code}, Length: {resp_length}B)")

        return result

    except requests.exceptions.RequestException as e:
        if verbose:
            print(f"[!] Request exception for {target_url}: {e}")
        pass

    return None

def analyze_timing_leak(all_results):
    """Analyzes response times per username to detect timing-based user enumeration vulnerabilities."""
    user_times = defaultdict(list)
    for res in all_results:
        if res and not res.get('success'):
            user_times[res['username']].append(res['response_time'])

    if len(user_times) < 2:
        return []

    averages = {user: sum(times)/len(times) for user, times in user_times.items() if times}
    if not averages:
        return []

    overall_avg = sum(averages.values()) / len(averages)
    vulnerabilities = []

    print("\n" + "="*60 + "\n[*] Timing-Based User Enumeration Analysis:")
    for user, avg_time in averages.items():
        diff_pct = abs(avg_time - overall_avg) / overall_avg * 100 if overall_avg > 0 else 0
        print(f"    - User '{user}': Avg Response Time = {avg_time:.3f}s ({diff_pct:.1f}% deviation)")
        if diff_pct > 35 and avg_time > overall_avg:
            vulnerabilities.append({
                "username": user,
                "avg_time": avg_time,
                "deviation": diff_pct
            })

    if vulnerabilities:
        print("\n[!] [POTENTIAL VULNERABILITY] Significant timing variance detected!")
    else:
        print("    [+] No significant timing anomalies detected across usernames.")
    print("="*60)
    return vulnerabilities

def analyze_length_outliers(all_results):
    """Clusters response lengths to detect structural outliers or hidden states."""
    lengths = [res['response_length'] for res in all_results if res and not res.get('success')]
    if not lengths:
        return []

    length_counts = Counter(lengths)
    baseline_length, baseline_count = length_counts.most_common(1)[0]
    
    outliers = []
    print("\n" + "="*60 + "\n[*] Response Length Clustering & Outlier Analysis:")
    print(f"    - Baseline Failure Length: {baseline_length} bytes ({baseline_count} occurrences)")

    for res in all_results:
        if res and not res.get('success'):
            l = res['response_length']
            if l != baseline_length:
                diff = abs(l - baseline_length)
                print(f"    [!] Outlier detected -> User: {res['username']}, Password: {res['password']} | Length: {l}B (Diff: {diff:+d}B)")
                outliers.append({
                    "username": res['username'],
                    "password": res['password'],
                    "length": l,
                    "baseline_diff": diff,
                    "status_code": res['status_code']
                })

    if not outliers:
        print("    [+] All failed responses conform to uniform length baseline.")
    print("="*60)
    return outliers

def export_html_report(findings, timing_vulns, length_outliers, report_path, metadata):
    """Generates a professional, styled HTML security report including session state details."""
    rows_html = ""
    for item in findings:
        cookies_str = str(item.get('session_cookies', {})).replace("{", "").replace("}", "")
        rows_html += f"""
        <tr>
            <td><code>{item['username']}</code></td>
            <td><code>{item['password']}</code></td>
            <td><a href="{item['endpoint']}" target="_blank">{item['endpoint']}</a></td>
            <td><code>{item['type'].upper()}</code></td>
            <td><code>{cookies_str if cookies_str else 'N/A'}</code></td>
            <td><code>{item['status_code']}</code></td>
        </tr>
        """

    if not rows_html:
        rows_html = '<tr><td colspan="6" class="no-findings">No valid credentials discovered during this scan.</td></tr>'

    timing_html = ""
    if timing_vulns:
        timing_rows = "".join([f"<tr><td><code>{v['username']}</code></td><td>{v['avg_time']:.3f}s</td><td style='color: #ef4444;'>+{v['deviation']:.1f}% slower</td></tr>" for v in timing_vulns])
        timing_html = f"""
        <h2 style="margin-top: 40px; color: #f59e0b;">⚠️ Potential User Enumeration (Timing Anomalies)</h2>
        <table>
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Average Response Time</th>
                    <th>Anomaly Deviation</th>
                </tr>
            </thead>
            <tbody>
                {timing_rows}
            </tbody>
        </table>
        """

    outliers_html = ""
    if length_outliers:
        outlier_rows = "".join([f"<tr><td><code>{o['username']}</code></td><td><code>{o['password']}</code></td><td>{o['length']} bytes</td><td style='color: #38bdf8;'>{o['baseline_diff']:+d} bytes</td></tr>" for o in length_outliers])
        outliers_html = f"""
        <h2 style="margin-top: 40px; color: #38bdf8;">📊 Response Length Outliers & Anomalies</h2>
        <table>
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Password Tested</th>
                    <th>Response Length</th>
                    <th>Baseline Difference</th>
                </tr>
            </thead>
            <tbody>
                {outlier_rows}
            </tbody>
        </table>
        """

    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Audit Report - Auth Analyzer</title>
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-color: #f8fafc;
            --text-muted: #94a3b8;
            --accent-green: #22c55e;
            --accent-blue: #38bdf8;
            --border-color: #334155;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 40px;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
        }
        header {
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        h1 {
            margin: 0 0 10px 0;
            font-size: 24px;
            color: var(--accent-blue);
        }
        .meta-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            background: var(--card-bg);
            padding: 20px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            margin-bottom: 30px;
        }
        .meta-item span {
            display: block;
            font-size: 12px;
            color: var(--text-muted);
            text-transform: uppercase;
            margin-bottom: 4px;
        }
        .meta-item strong {
            font-size: 16px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background: var(--card-bg);
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid var(--border-color);
            margin-bottom: 20px;
        }
        th, td {
            padding: 14px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        th {
            background-color: #111827;
            font-size: 13px;
            text-transform: uppercase;
            color: var(--text-muted);
        }
        tr:last-child td {
            border-bottom: none;
        }
        a {
            color: var(--accent-blue);
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        code {
            background: #0f172a;
            padding: 4px 8px;
            border-radius: 4px;
            font-family: monospace;
        }
        .no-findings {
            text-align: center;
            color: var(--text-muted);
            padding: 40px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Security Audit & Authentication Report</h1>
            <p style="color: var(--text-muted); margin: 0;">Generated by <code>term_analyzer.py</code></p>
        </header>

        <div class="meta-grid">
            <div class="meta-item">
                <span>Target URL</span>
                <strong>__URL__</strong>
            </div>
            <div class="meta-item">
                <span>Auth Type</span>
                <strong>__AUTH_TYPE__</strong>
            </div>
            <div class="meta-item">
                <span>Scan Duration</span>
                <strong>__DURATION__</strong>
            </div>
            <div class="meta-item">
                <span>Valid Credentials Found</span>
                <strong style="color: var(--accent-green);">__TOTAL_FINDINGS__</strong>
            </div>
        </div>

        <h2>Discovered Credentials & Harvested Sessions</h2>
        <table>
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Password</th>
                    <th>Endpoint</th>
                    <th>Protocol</th>
                    <th>Harvested Cookies / Tokens</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                __ROWS_HTML__
            </tbody>
        </table>

        __TIMING_HTML__
        __OUTLIERS_HTML__
    </div>
</body>
</html>
"""

    html_content = (
        html_template
        .replace("__URL__", metadata['url'])
        .replace("__AUTH_TYPE__", metadata['auth_type'].upper())
        .replace("__DURATION__", metadata['duration'])
        .replace("__TOTAL_FINDINGS__", str(len(findings)))
        .replace("__ROWS_HTML__", rows_html)
        .replace("__TIMING_HTML__", timing_html)
        .replace("__OUTLIERS_HTML__", outliers_html)
    )

    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    print(f"[*] Professional HTML report successfully exported to {report_path}")

def run_analysis(args):
    usernames = load_wordlist(args.users)
    passwords = load_wordlist(args.passwords)
    
    if not usernames:
        usernames = ["admin", "root", "user"]
    if not passwords:
        passwords = ["password", "123456", "admin"]

    if args.mutate:
        original_count = len(passwords)
        passwords = mutate_passwords(passwords)
        print(f"[*] Password Mutation Enabled: Expanded wordlist from {original_count} to {len(passwords)} candidates.")

    proxy_pool = ProxyPool(args.proxy_file) if args.proxy_file else None
    base_headers = parse_custom_headers(args.header)
    cookies = parse_cookies(args.cookie)
    circuit_breaker = CircuitBreaker(threshold=args.lockout_threshold)

    session = requests.Session()

    print(f"[*] Loaded {len(usernames)} username(s) and {len(passwords)} password(s).")
    print(f"[*] Auth Type: {args.auth_type.upper()} | Content-Type: {args.content_type.upper()}")

    if args.enum_users:
        run_user_enumeration(
            session, args.url, usernames, args.auth_type, args.content_type,
            args.user_field, args.pass_field, proxy_pool, args.proxy, base_headers,
            cookies, args.extract_csrf, args.csrf_field, args.probe_password,
            args.delay, args.threads, args.verbose
        )

    print(f"[*] Running password audit with max {args.threads} concurrent threads...\n" + "-" * 60)

    tasks = [(user, pwd) for user in usernames for pwd in passwords]
    all_results = []
    valid_credentials = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [
            executor.submit(
                test_auth, session, args.url, user, pwd, args.auth_type,
                args.content_type, args.user_field, args.pass_field, args.failure_keyword, 
                args.success_regex, proxy_pool, args.proxy, base_headers, 
                cookies, circuit_breaker, args.extract_csrf, args.csrf_field, 
                args.delay, args.lockout_keyword, args.verbose
            )
            for user, pwd in tasks
        ]

        for future in as_completed(futures):
            if circuit_breaker.is_tripped():
                break
            res = future.result()
            if res:
                all_results.append(res)
                if res['success']:
                    valid_credentials.append({
                        "username": res['username'],
                        "password": res['password'],
                        "endpoint": res['endpoint'],
                        "type": res['type'],
                        "status_code": res['status_code'],
                        "session_cookies": res['session_cookies'],
                        "session_headers": res['session_headers'],
                        "jwt_candidates": res.get('jwt_candidates', [])
                    })

    if circuit_breaker.is_tripped():
        print("\n[!] Scan aborted early due to Circuit Breaker trip (Account Lockout Safeguard activated).")

    # Automated JWT auditing on harvested tokens if enabled
    if args.jwt_audit:
        audited_tokens = set()
        for item in valid_credentials:
            for t in item.get('jwt_candidates', []):
                audited_tokens.add(t)
        if args.jwt_token:
            audited_tokens.add(args.jwt_token)

        if audited_tokens:
            for jwt_str in audited_tokens:
                audit_jwt_token(jwt_str, args.jwt_secrets)
        else:
            print("\n" + "="*60 + "\n[*] Automated JWT Audit: No JWT tokens were captured in responses or specified.")
            print("="*60)

    # Automated MFA Flow Auditing if enabled
    if args.mfa_mode and args.mfa_url:
        otp_codes = load_wordlist(args.otp_list)
        if not otp_codes:
            otp_codes = ["0000", "1234", "1111", "9999", "", "000000", "123456"]
        audit_mfa_flow(session, args.mfa_url, args.otp_field, otp_codes, proxy_pool, args.proxy, base_headers, cookies)

    timing_vulns = []
    if args.timing_analysis:
        timing_vulns = analyze_timing_leak(all_results)

    length_outliers = []
    if args.detect_length_outliers:
        length_outliers = analyze_length_outliers(all_results)

    return valid_credentials, timing_vulns, length_outliers

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Security Analyzer with MFA Flow Auditing")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--auth-type", choices=["form", "basic", "digest"], default="form", help="Authentication type to test")
    parser.add_argument("--content-type", choices=["form", "json"], default="form", help="Payload content type for form/API auth")
    parser.add_argument("--extract-csrf", action="store_true", help="Automatically scrape and inject anti-CSRF token")
    parser.add_argument("--csrf-field", default="csrf_token", help="Name of the form/JSON field for CSRF token")
    parser.add_argument("--enum-users", action="store_true", help="Enable dedicated account enumeration mode")
    parser.add_argument("--probe-password", default="invalidprobe12345!", help="Dummy password used during user enumeration probe")
    parser.add_argument("--mutate", action="store_true", help="Enable smart password mutation & rule engine")
    parser.add_argument("--jwt-audit", action="store_true", help="Enable automated JWT security audit and secret cracking")
    parser.add_argument("--jwt-token", help="Explicit JWT token string to audit")
    parser.add_argument("--jwt-secrets", default="passwords.txt", help="Wordlist for JWT HMAC secret cracking")
    parser.add_argument("--mfa-mode", action="store_true", help="Enable MFA / OTP verification flow auditing")
    parser.add_argument("--mfa-url", help="Target endpoint for secondary MFA/OTP verification")
    parser.add_argument("--otp-field", default="otp_code", help="Form field name for the OTP/verification code")
    parser.add_argument("--otp-list", default="passwords.txt", help="Wordlist file containing candidate OTP/PIN codes")
    parser.add_argument("--users", default="usernames.txt", help="Path to usernames wordlist")
    parser.add_argument("--passwords", default="passwords.txt", help="Path to passwords wordlist")
    parser.add_argument("--user-field", default="username", help="Payload field name for username")
    parser.add_argument("--pass-field", default="password", help="Payload field name for password")
    parser.add_argument("--failure-keyword", default="invalid", help="Keyword in response indicating failure")
    parser.add_argument("--success-regex", help="Regular expression matching successful response body")
    parser.add_argument("--lockout-keyword", help="Keyword or phrase indicating lockout or rate limit")
    parser.add_argument("--lockout-threshold", type=int, default=3, help="Consecutive lockouts before tripping circuit breaker")
    parser.add_argument("-H", "--header", action="append", help="Custom HTTP header")
    parser.add_argument("--cookie", help="Custom cookies string")
    parser.add_argument("--delay", type=float, default=0.0, help="Base delay in seconds")
    parser.add_argument("--timing-analysis", action="store_true", help="Enable side-channel timing analysis")
    parser.add_argument("--detect-length-outliers", action="store_true", help="Enable response length clustering")
    parser.add_argument("--save-session", default="sessions.json", help="File to save harvested session cookies and tokens")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("--proxy", help="Route traffic through static proxy")
    parser.add_argument("--proxy-file", help="Path to proxy list file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug output")
    parser.add_argument("-o", "--output", help="Save results to JSON file")
    parser.add_argument("--report", help="Generate professional HTML security report")

    args = parser.parse_args()

    print(f"[*] Starting Auth analysis on: {args.url}")
    start_time = datetime.now()
    
    found, timing_vulns, length_outliers = run_analysis(args)

    duration = datetime.now() - start_time
    duration_str = f"{duration.total_seconds():.2f}s"
    print(f"\n[+] Scan Complete in {duration_str}. Total valid items found: {len(found)}")

    if found:
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(found, f, indent=4)
            print(f"[*] Results successfully exported to JSON: {args.output}")

        if args.save_session:
            with open(args.save_session, 'w', encoding='utf-8') as f:
                json.dump([{ "username": item["username"], "cookies": item["session_cookies"], "headers": item["session_headers"], "jwt_candidates": item.get("jwt_candidates", []) } for item in found], f, indent=4)
            print(f"[*] Harvested session state successfully saved to: {args.save_session}")

    if args.report:
        metadata = {
            "url": args.url,
            "auth_type": args.auth_type,
            "duration": duration_str
        }
        export_html_report(found, timing_vulns, length_outliers, args.report, metadata)
