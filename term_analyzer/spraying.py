import requests
from requests.auth import HTTPBasicAuth
from term_analyzer.defaults import get_defaults_for_port
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import os

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

def test_http_auth(host, port, username, password):
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{host}:{port}/"
    try:
        response = requests.get(url, auth=HTTPBasicAuth(username, password), timeout=3)
        if response.status_code in [200, 302, 204]:
            return True, f"HTTP Success (Status: {response.status_code})"
        elif response.status_code == 401:
            return False, "Unauthorized (401)"
        else:
            return False, f"Unexpected Status: {response.status_code}"
    except requests.exceptions.RequestException as e:
        return False, f"Connection Error: {e}"

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

def perform_auth_check(target_host, port, username, password):
    if port == 22:
        return test_ssh_auth(target_host, port, username, password)
    elif port in [80, 443, 8080]:
        return test_http_auth(target_host, port, username, password)
    elif port == 3306:
        return test_mysql_auth(target_host, port, username, password)
    elif port == 5432:
        return test_postgresql_auth(target_host, port, username, password)
    else:
        return False, "Service protocol handler not implemented yet"

def run_credential_spray(target_host, open_ports, user_arg=None, password_arg=None, user_file=None, password_file=None, max_threads=5):
    """
    Executes live multithreaded credential spraying using defaults, CLI args, or wordlist files.
    """
    results = []
    tasks = []

    for port in open_ports:
        # Resolve usernames
        file_users = load_wordlist(user_file)
        if file_users:
            usernames = file_users
        elif user_arg:
            usernames = [u.strip() for u in user_arg.split(",")]
        else:
            usernames = [u for u, _ in get_defaults_for_port(port)]

        # Resolve passwords
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
        success, msg = perform_auth_check(target_host, port, username, password)
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

    print(f"[*] Starting multithreaded spray across {len(tasks)} total checks using {max_threads} threads...")
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(worker, port, u, p): (port, u, p) for port, u, p in tasks}
        for future in as_completed(futures):
            try:
                res = future.result()
                results.append(res)
            except Exception as e:
                pass

    return results
