import urllib.request
import hashlib
import base64

url = "https://helloretailcdn.com/helloretail.js"
print(f"[*] Fetching external asset with browser headers: {url}")

try:
    # Use browser headers to bypass CDN bot detection (403 Forbidden)
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    req_obj = urllib.request.Request(url, headers=headers)
    
    with urllib.request.urlopen(req_obj) as req:
        content = req.read()
    
    # Calculate SHA-384 SRI hash
    digest = hashlib.sha384(content).digest()
    sri_hash = "sha384-" + base64.b64encode(digest).decode("utf-8")
    print(f"[+] Computed SRI Hash: {sri_hash}")
    
    # Update index.html automatically
    with open("index.html", "r") as f:
        html = f.read()
        
    # Replace un-hashed script tag with the cryptographically secured version
    old_tag = '<script src="https://helloretailcdn.com/helloretail.js"></script>'
    new_tag = f'<script src="{url}" integrity="{sri_hash}" crossorigin="anonymous"></script>'
    
    if old_tag in html:
        updated_html = html.replace(old_tag, new_tag)
        with open("index.html", "w") as f:
            f.write(updated_html)
        print("[+] Successfully updated index.html with SRI hash and crossorigin attribute!")
    else:
        print("[-] Target script tag not matched exactly in index.html.")
except Exception as e:
    print(f"[-] Error: {e}")
