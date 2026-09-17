import urllib.request, urllib.error

target = "https://medistore.se"
sensitive_endpoints = [
    "/wp-json/code-snippets/v1/",
    "/wp-json/wc/private/",
    "/wp-json/advanced-db-cleaner/v1/",
    "/wp-json/swish/"
]

print(f"[*] Testing security boundaries on sensitive namespaces:\n")
for ep in sensitive_endpoints:
    url = target + ep
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req) as resp:
            print(f"[!] [HTTP {resp.status}] PUBLIC ACCESSIBLE: {url}")
    except urllib.error.HTTPError as e:
        print(f"[+] [HTTP {e.code} Protected] {url}")
    except Exception as e:
        print(f"[-] [Error/Blocked] {url}")
