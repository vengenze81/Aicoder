import requests
from requests.auth import HTTPBasicAuth
from term_analyzer.defaults import get_defaults_for_port
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import os
import time
from ftplib import FTP, error_perm

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

try:
    import pymysql
    PYMYSQL_AVAILABLE = True
except ImportError:
    PYMYSQL_AVAILABLE = False

try:
    import psycopg2
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False

print_lock = threading.Lock()

def load_wordlist(file_path):
    """Reads a text file and returns a list of cleaned, non-empty lines."""
    if not file_path or not os.path.exists(file_path):
        return []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except Exception as e:
        print(f"[-] Error reading wordlist {file_path}: {e}")
        return []

def parse_headers(header_args):
    """Parses a list of key:value header strings into a dictionary."""
    headers = {}
    if not header_args:
        return headers
    for h in header_args:
        if ":" in h:
            key, val = h.split(":", 1)
            headers[key.strip()] = val.strip()
    return headers

def test_ftp_auth(host, port, username, password):
    """Tests FTP authentication against port 21."""
    try:
        ftp = FTP()
        ftp.connect(host, port=port, timeout=3)
        ftp.login(user=username, passwd=password)
        ftp.quit()
        return True, "FTP Login Successful!"
    except error_perm as e:
        err_str = str(e)
        if "530" in err_str or "Login incorrect" in err_str:
            return False, "Authentication Failed (530)"
        return False, f"FTP Perm Error: {err_str}"
    except Exception as e:
        return False, f"FTP Error: {e}"

def test_http_auth(host, port, username, password, custom_headers=None):
    """Tests HTTP/HTTPS authentication with browser headers and protocol fallback."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }
    if custom_headers:
        headers.update(parse_headers(custom_headers))

    # Automatically try HTTPS first if port is 443 or 8080, with HTTP fallback (or vice versa)
    schemes = ["https", "http"] if port in [443, 8080] else ["http", "https"]
    
    last_error = ""
    for scheme in schemes:
        url = f"{scheme}://{host}:{port}/"
        try:
            # Disable SSL verification warnings for self-signed audit certificates
            response = requests.get(url, auth=HTTPBasicAuth(username, password), headers=headers, timeout=3, allow_redirects=True, verify=False)
            if response.status_code in [200, 302, 204]:
                return True, f"HTTP Success ({scheme.upper()}) (Status: {response.status_code})"
            elif response.status_code == 401:
                return False, f"Unauthorized (401) on {scheme.upper()}"
            else:
                return False, f"Unexpected Status: {response.status_code} ({scheme.upper()})"
        except requests.exceptions.SSLError:
            last_error = "SSL Certificate Error"
            continue
        except requests.exceptions.ConnectionError:
            last_error = f"Connection Dropped / Reset ({scheme.upper()})"
            continue
        except requests.exceptions.Timeout:
            last_error = "Request Timeout"
            continue
        except Exception as e:
            last_error = f"Error: {e}"
            continue

    return False, last_error or "Connection Aborted by Remote Host"

def test_ssh_auth(host, port, username, password):
    if not PARAMIKO_AVAILABLE:
        return False, "Paramiko library not installed"
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, port=port, username=username, password=password, timeout=3, allow_agent=False, look_for_keys=False)
        return True, "SSH Login Successful!"
    except paramiko.AuthenticationException:
        return False, "Authentication Failed"
    except Exception as e:
        return False, f"SSH Error: {e}"
    finally:
        ssh.close()

def test_mysql_auth(host, port, username, password):
    if not PYMYSQL_AVAILABLE:
        return False, "pymysql library not installed"
    try:
        conn = pymysql.connect(host=host, port=port, user=username, password=password, connect_timeout=3)
        conn.close()
        return True, "MySQL Login Successful!"
    except pymysql.err.OperationalError as e:
        code = e.args[0] if e.args else 0
        if code == 1045:
            return False, "Access Denied (Invalid Credentials)"
        return False, f"MySQL Error: {e}"
    except Exception as e:
        return False, f"MySQL Error: {e}"

def test_postgresql_auth(host, port, username, password):
    if not PSYCOPG2_AVAILABLE:
        return False, "psycopg2 library not installed"
    try:
        conn = psycopg2.connect(host=host, port=port, user=username, password=password, dbname="postgres", connect_timeout=3)
        conn.close()
        return True, "PostgreSQL Login Successful!"
    except Exception as e:
        err_msg = str(e).strip()
        if "password authentication failed" in err_msg:
            return False, "Authentication Failed"
        return False, f"PostgreSQL Error: {err_msg}"

def perform_auth_check(target_host, port, username, password, custom_headers=None):
    if port == 21:
        return test_ftp_auth(target_host, port, username, password)
    elif port == 22:
        return test_ssh_auth(target_host, port, username, password)
    elif port in [80, 443, 8080]:
        return test_http_auth(target_host, port, username, password, custom_headers=custom_headers)
    elif port == 3306:
        return test_mysql_auth(target_host, port, username, password)
    elif port == 5432:
        return test_postgresql_auth(target_host, port, username, password)
    else:
        return False, "Service protocol handler not implemented yet"

def run_credential_spray(target_host, open_ports, user_arg=None, password_arg=None, user_file=None, password_file=None, max_threads=5, delay=0.0, custom_headers=None):
    """
    Executes live multithreaded credential spraying with smart HTTP handling.
    """
    results = []
    tasks = []

    for port in open_ports:
        file_users = load_wordlist(user_file)
        if file_users:
            usernames = file_users
        elif user_arg:
            usernames = [u.strip() for u in user_arg.split(",")]
        else:
            usernames = [u for u, _ in get_defaults_for_port(port)]

        file_passwords = load_wordlist(password_file)
        if file_passwords:
            passwords = file_passwords
        elif password_arg:
            passwords = [password_arg]
        else:
            passwords = [p for _, p in get_defaults_for_port(port)]

        pairs = [(u, p) for u in usernames for p in passwords]
        print(f"[*] Loaded {len(pairs)} credential combination(s) for port {port}")

        for username, password in pairs:
            tasks.append((port, username, password))

    def worker(port, username, password):
        if delay > 0:
            time.sleep(delay)
        success, msg = perform_auth_check(target_host, port, username, password, custom_headers=custom_headers)
        with print_lock:
            if success:
                print(f"[*] Testing {username}:{password} on {target_host}:{port}... \033[92m[SUCCESS] {msg}\033[0m")
            else:
                print(f"[*] Testing {username}:{password} on {target_host}:{port}... \033[91m[-] {msg}\033[0m")
        return {
            "target": target_host,
            "port": port,
            "username": username,
            "password": password,
            "success": success,
            "message": msg
        }

    print(f"[*] Starting multithreaded spray across {len(tasks)} total checks using {max_threads} threads (Delay: {delay}s)...")
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(worker, port, u, p): (port, u, p) for port, u, p in tasks}
        for future in as_completed(futures):
            try:
                res = future.result()
                results.append(res)
            except Exception as e:
                pass

    return results
