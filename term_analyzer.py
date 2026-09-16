import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
import urllib3
import os
import argparse
import json
import re
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

def test_digest_auth(session, target_url, path, username, password, verbose=False):
    """Tests HTTP Digest Authentication."""
    url = f"{target_url.rstrip('/')}{path}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    
    try:
        baseline = session.get(url, headers=headers, timeout=5, allow_redirects=True, verify=False)
        if baseline.status_code == 404:
            return None

        # Check for Digest challenge in WWW-Authenticate header
        auth_header = baseline.headers.get('WWW-Authenticate', '')
        if baseline.status_code != 401 or 'Digest' not in auth_header:
            return None

        resp = session.get(url, auth=HTTPDigestAuth(username, password), headers=headers, timeout=5, allow_redirects=True, verify=False)
        if resp.status_code in [200, 204, 302] and resp.status_code != 401:
            return {
                "username": username,
                "password": password,
                "endpoint": url,
                "type": "digest",
                "status_code": resp.status_code
            }
        elif verbose:
            print(f"[-] Failed digest login {username}:{password} at {url} (Status: {resp.status_code})")
    except requests.exceptions.RequestException:
        pass
    return None

def test_form_auth(session, target_url, username, password, user_field, pass_field, failure_keyword, verbose=False):
    """Tests HTML Form-Based Authentication with automated hidden input/CSRF scraping."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    try:
        get_resp = session.get(target_url, headers=headers, timeout=5, allow_redirects=True, verify=False)
        
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

        resp = session.post(
            target_url,
            data=payload,
            headers=headers,
            timeout=5,
            allow_redirects=True,
            verify=False
        )

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

def test_api_token(session, target_url, token, header_format, verbose=False):
    """Tests API Token / Bearer Token validation against an endpoint."""
    # Format the header value (e.g., "Bearer <token>" or just "<token>")
    token_header_value = header_format.replace("{token}", token)
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Authorization": token_header_value
    }

    try:
        resp = session.get(target_url, headers=headers, timeout=5, allow_redirects=True, verify=False)
        
        # Successful API token requests typically return 200 OK or 204 No Content
        if resp.status_code in [200, 204]:
            return {
                "username": "API-Token",
                "password": token[:10] + "..." if len(token) > 10 else token,
                "endpoint": target_url,
                "type": "api-token",
                "status_code": resp.status_code
            }
        elif verbose:
            print(f"[-] Invalid API token: {token[:6]}... (Status: {resp.status_code})")
    except requests.exceptions.RequestException:
        pass
    return None

def export_html_report(findings, report_path, metadata):
    """Generates a professional, styled HTML security report using safe replacement."""
    rows_html = ""
    for item in findings:
        rows_html += f"""
        <tr>
            <td><code>{item['username']}</code></td>
            <td><code>{item['password']}</code></td>
            <td><a href="{item['endpoint']}" target="_blank">{item['endpoint']}</a></td>
            <td><span class="badge {item['type']}">{item['type'].upper()}</span></td>
            <td><code>{item['status_code']}</code></td>
        </tr>
        """

    if not rows_html:
        rows_html = '<tr><td colspan="5" class="no-findings">No valid credentials discovered during this scan.</td></tr>'

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
        .badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
        }
        .badge.basic { background: #0284c7; color: #fff; }
        .badge.form { background: #7c3aed; color: #fff; }
        .badge.digest { background: #0d9488; color: #fff; }
        .badge.api-token { background: #d97706; color: #fff; }
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

        <h2>Discovered Credentials / Tokens</h2>
        <table>
            <thead>
                <tr>
                    <th>Username / Subject</th>
                    <th>Password / Token</th>
                    <th>Endpoint / URL</th>
                    <th>Type</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                __ROWS_HTML__
            </tbody>
        </table>
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
    )

    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    print(f"[*] Professional HTML report successfully exported to {report_path}")

def run_analysis(args):
    usernames = load_wordlist(args.users)
    passwords = load_wordlist(args.passwords)
    paths = load_wordlist(args.paths) if args.paths else []

    if args.auth_type == "api-token":
        # For API tokens, passwords.txt functions as the token list
        tokens = passwords if passwords else usernames
        print(f"[*] Loaded {len(tokens)} API token(s) to test.")
        print(f"[*] Auth Type: API-TOKEN")
        print(f"[*] Running with max {args.threads} concurrent threads...\n" + "-" * 60)

        valid_credentials = []
        session = requests.Session()
        if args.proxy:
            session.proxies = {"http": args.proxy, "https": args.proxy}

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = [executor.submit(test_api_token, session, args.url, token, args.api_header, args.verbose) for token in tokens]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    valid_credentials.append(result)
                    print(f"\n[+] [SUCCESS] Valid API token found -> {result['password']} at {result['endpoint']}\n")
        return valid_credentials

    # Standard user/pass auth types
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
    elif args.auth_type == "digest":
        if not paths:
            paths = ["/", "/login", "/admin", "/api", "/secure"]
        for user in usernames:
            for pwd in passwords:
                for path in paths:
                    tasks.append(('digest', user, pwd, path))
    else: # form
        for user in usernames:
            for pwd in passwords:
                tasks.append(('form', user, pwd, args.url))

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for task in tasks:
            if task[0] == 'basic':
                futures.append(executor.submit(test_basic_auth, session, args.url, task[3], task[1], task[2], args.verbose))
            elif task[0] == 'digest':
                futures.append(executor.submit(test_digest_auth, session, args.url, task[3], task[1], task[2], args.verbose))
            else:
                futures.append(executor.submit(test_form_auth, session, args.url, task[1], task[2], args.user_field, args.pass_field, args.failure_keyword, args.verbose))

        for future in as_completed(futures):
            result = future.result()
            if result:
                valid_credentials.append(result)
                print(f"\n[+] [SUCCESS] Valid login found -> {result['username']}:{result['password']} at {result['endpoint']} (Type: {result['type']})\n")

    return valid_credentials

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Security Analyzer for Multiple Authentication Protocols")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--auth-type", choices=["basic", "form", "digest", "api-token"], default="basic", help="Authentication type to test")
    parser.add_argument("--users", default="usernames.txt", help="Path to usernames wordlist")
    parser.add_argument("--passwords", default="passwords.txt", help="Path to passwords wordlist (or token list for api-token)")
    parser.add_argument("--paths", help="Path to endpoints wordlist (Basic/Digest Auth only)")
    parser.add_argument("--user-field", default="username", help="Form field name for username (Form Auth only)")
    parser.add_argument("--pass-field", default="password", help="Form field name for password (Form Auth only)")
    parser.add_argument("--failure-keyword", default="invalid", help="Keyword in response body indicating login failure (Form Auth only)")
    parser.add_argument("--api-header", default="Bearer {token}", help="Header template for API tokens (API-Token Auth only)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("--proxy", help="Route traffic through a proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug output")
    parser.add_argument("-o", "--output", help="Save results to a JSON file")
    parser.add_argument("--report", help="Generate a professional HTML security report (e.g., report.html)")

    args = parser.parse_args()

    print(f"[*] Starting Auth analysis on: {args.url}")
    start_time = datetime.now()
    
    found = run_analysis(args)

    duration = datetime.now() - start_time
    duration_str = f"{duration.total_seconds():.2f}s"
    print(f"\n[+] Scan Complete in {duration_str}. Total valid items found: {len(found)}")

    if args.output and found:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(found, f, indent=4)
        print(f"[*] Results successfully exported to JSON: {args.output}")

    if args.report:
        metadata = {
            "url": args.url,
            "auth_type": args.auth_type,
            "duration": duration_str
        }
        export_html_report(found, args.report, metadata)
