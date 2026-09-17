import urllib.request, urllib.error

target = "https://medistore.se"
sub_endpoints = [
    "/wp-json/code-snippets/v1/snippets",
    "/wp-json/advanced-db-cleaner/v1/tables",
    "/wp-json/wc/private/settings"
]

print("[*] Testing access to specific plugin sub-endpoints:\n")
for ep in sub_endpoints:
    url = target + ep
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req) as resp:
            print(f"[!] [HTTP {resp.status}] FULLY PUBLIC DATA ACCESS: {url}")
    except urllib.error.HTTPError as e:
        print(f"[+] [HTTP {e.code} Protected] Sub-endpoint secured: {url}")
    except Exception as e:
        print(f"[-] [Error] {url} ({e})")
