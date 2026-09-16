import json
import base64
import hmac
import hashlib
import asyncio
import urllib.request
from rich.console import Console

console = Console()

WORDLIST_URLS = {
    "jwt": {
        "url": "https://raw.githubusercontent.com/ticarpi/jwt_tool/master/jwt-common.txt",
        "output": "jwt_secrets.txt"
    },
    "directories": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
        "output": "directories.txt"
    },
    "parameters": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt",
        "output": "parameters.txt"
    }
}

def download_wordlist(wordlist_type="jwt"):
    """Downloads a standard security wordlist from official GitHub repositories."""
    config = WORDLIST_URLS.get(wordlist_type)
    if not config:
        available = ", ".join(WORDLIST_URLS.keys())
        console.print(f"[bold red][!] Unknown wordlist type '{wordlist_type}'. Choose from: {available}[/bold red]")
        return False
        
    url = config["url"]
    output_filename = config["output"]
    console.print(f"[bold cyan][*] Downloading '{wordlist_type}' wordlist into {output_filename}...[/bold cyan]")
    try:
        urllib.request.urlretrieve(url, output_filename)
        console.print(f"[bold green][+] Successfully downloaded wordlist to: {output_filename}[/bold green]")
        return True
    except Exception as e:
        console.print(f"[bold red][!] Error downloading wordlist: {e}[/bold red]")
        return False

def base64url_decode(input_str):
    """Decodes base64url-encoded strings safely with proper padding."""
    input_str += "=" * (-len(input_str) % 4)
    return base64.urlsafe_b64decode(input_str.encode("utf-8"))

def decode_jwt(token):
    """Decodes a JWT header and payload without verifying signature."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None, None, "Invalid JWT format (must have 3 parts)"
            
        header_json = base64url_decode(parts[0]).decode("utf-8")
        payload_json = base64url_decode(parts[1]).decode("utf-8")
        
        header = json.loads(header_json)
        payload = json.loads(payload_json)
        return header, payload, None
    except Exception as e:
        return None, None, str(e)

def verify_hs256_signature(token, secret):
    """Verifies or computes an HS256 signature for a token using a candidate secret."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False
            
        message = f"{parts[0]}.{parts[1]}".encode("utf-8")
        secret_bytes = secret.encode("utf-8")
        
        signature = hmac.new(secret_bytes, message, hashlib.sha256).digest()
        sig_encoded = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("utf-8")
        
        return sig_encoded == parts[2]
    except Exception:
        return False

async def brute_force_jwt(token, wordlist_path, concurrency=50):
    """Asynchronously brute-forces a weak HS256 JWT secret using a wordlist."""
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            secrets = [line.strip() for line in f if line.strip()]
    except Exception as e:
        console.print(f"[bold red][!] Error loading wordlist {wordlist_path}: {e}[/bold red]")
        return None

    header, payload, err = decode_jwt(token)
    if err:
        console.print(f"[bold red][!] {err}[/bold red]")
        return None

    console.print(f"[bold cyan][*] Loaded {len(secrets)} secrets. Starting HS256 JWT brute-force...[/bold cyan]")
    
    found_secret = None
    for secret in secrets:
        if verify_hs256_signature(token, secret):
            found_secret = secret
            break
            
    return found_secret
