import urllib.request
import json

url = "https://medistore.se/wp-json/"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})

try:
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        namespaces = data.get("namespaces", [])
        print(f"[*] Found {len(namespaces)} active WP-JSON namespaces:\n")
        for ns in sorted(namespaces):
            print(f"  - {ns}")
except Exception as e:
    print(f"[-] Error fetching namespaces: {e}")
