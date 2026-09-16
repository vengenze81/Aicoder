import json
import base64
import hmac
import hashlib
import os
import urllib.request
from rich.console import Console

console = Console()

WORDLIST_URLS = {
    "jwt": "https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt_secrets.txt",
    "directories": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt",
    "parameters": "https://raw.githubusercontent.com/assetnote/wordlists-research/master/data/top-params.txt",
    "subdomains": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"
}

def download_wordlist(wordlist_type):
    """Downloads standard security wordlists from official GitHub repositories."""
    if wordlist_type not in WORDLIST_URLS:
        console.print(f"[bold red][!] Unknown wordlist type: {wordlist_type}. Choose from: {list(WORDLIST_URLS.keys())}[/bold red]")
        return
        
    url = WORDLIST_URLS[wordlist_type]
    filename = f"{wordlist_type}.txt"
    
    console.print(f"[bold cyan][*] Downloading {wordlist_type} wordlist from {url} ...[/bold cyan]")
    try:
        urllib.request.urlretrieve(url, filename)
        console.print(f"[bold green][+] Successfully downloaded and saved as '{filename}'[/bold green]")
    except Exception as e:
        console.print(f"[bold red][!] Failed to download wordlist: {e}[/bold red]")

def base64_url_decode(input_str):
    padding = '=' * (4 - (len(input_str) % 4))
    return base64.urlsafe_b64decode(input_str + padding)

def decode_jwt(token):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None, None, "Invalid JWT structure (expected 3 parts)"
        header = json.loads(base64_url_decode(parts[0]).decode('utf-8'))
        payload = json.loads(base64_url_decode(parts[1]).decode('utf-8'))
        return header, payload, None
    except Exception as e:
        return None, None, str(e)

async def brute_force_jwt(token, wordlist_path):
    parts = token.split('.')
    if len(parts) != 3:
        console.print("[bold red][!] Invalid JWT token format.[/bold red]")
        return None
        
    message = f"{parts[0]}.{parts[1]}".encode('utf-8')
    try:
        signature = base64_url_decode(parts[2])
    except Exception as e:
        console.print(f"[bold red][!] Error decoding JWT signature: {e}[/bold red]")
        return None

    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            secrets = [line.strip() for line in f if line.strip()]
    except Exception as e:
        console.print(f"[bold red][!] Error reading wordlist: {e}[/bold red]")
        return None

    console.print(f"[bold cyan][*] Starting JWT brute-force using {len(secrets)} secrets from {wordlist_path}...[/bold cyan]")
    
    for secret in secrets:
        computed = hmac.new(secret.encode('utf-8'), message, hashlib.sha256).digest()
        if hmac.compare_digest(computed, signature):
            return secret
            
    return None
