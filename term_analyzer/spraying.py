import requests
from requests.auth import HTTPBasicAuth
from term_analyzer.defaults import get_defaults_for_port

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

def run_credential_spray(target_host, open_ports, user_arg, password_arg):
    """
    Executes live credential spraying and returns a list of result dictionaries.
    """
    results = []
    for port in open_ports:
        if password_arg or user_arg:
            usernames = [u.strip() for u in user_arg.split(",")] if user_arg else ["admin"]
            passwords = [password_arg] if password_arg else [pwd for _, pwd in get_defaults_for_port(port)]
            pairs = [(u, p) for u in usernames for p in passwords]
        else:
            pairs = get_defaults_for_port(port)
            print(f"[*] Loaded {len(pairs)} default credential pairs for port {port}")

        for username, password in pairs:
            print(f"[*] Testing {username}:{password} on {target_host}:{port}...", end=" ")
            
            success = False
            msg = ""
            if port == 22:
                success, msg = test_ssh_auth(target_host, port, username, password)
            elif port in [80, 443, 8080]:
                success, msg = test_http_auth(target_host, port, username, password)
            elif port == 3306:
                success, msg = test_mysql_auth(target_host, port, username, password)
            elif port == 5432:
                success, msg = test_postgresql_auth(target_host, port, username, password)
            else:
                msg = "Service protocol handler not implemented yet"

            if success:
                print(f"\033[92m[SUCCESS] {msg}\033[0m")
            else:
                print(f"\033[91m[-] {msg}\033[0m")

            results.append({
                "target": target_host,
                "port": port,
                "username": username,
                "password": password,
                "success": success,
                "message": msg
            })
    return results
