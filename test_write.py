import urllib.request, urllib.error, json

write_url = "https://blog.tidformera.se/feeds/posts/default"
payload = json.dumps({"title": {"$t": "Unauthorized Test Post"}}).encode("utf-8")

req_post = urllib.request.Request(
    write_url, 
    data=payload, 
    headers={
        "Content-Type": "application/json", 
        "User-Agent": "Mozilla/5.0"
    }, 
    method="POST"
)

try:
    with urllib.request.urlopen(req_post) as resp:
        print(f"[*] Status: {resp.status}")
        print(f"[*] Content-Type: {resp.headers.get('Content-Type')}")
        body = resp.read().decode("utf-8", errors="ignore")
        print(f"\n[*] Response Body Snippet:\n{body[:400]}")
except Exception as e:
    print(f"[-] Error: {e}")
