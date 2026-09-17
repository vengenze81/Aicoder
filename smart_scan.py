import urllib.request
import urllib.error
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

target_base = "https://blog.tidformera.se/"
wordlist_path = "wordlist.txt"

try:
    with open(wordlist_path, "r") as f:
        words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
except FileNotFoundError:
    print(f"[-] Error: Wordlist '{wordlist_path}' not found.")
    sys.exit(1)

print(f"[*] Starting fast multithreaded scan of {len(words)} entries...\n")

def check_path(word):
    url = f"{target_base}{word}"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return (word, response.status, len(response.read()))
    except urllib.error.HTTPError as e:
        if e.code not in [404, 503]:
            return (word, e.code, len(e.read()))
    except Exception:
        pass
    return None

# Run with 20 concurrent worker threads
with ThreadPoolExecutor(max_workers=20) as executor:
    futures = {executor.submit(check_path, word): word for word in words}
    for future in as_completed(futures):
        result = future.result()
        if result:
            word, status, length = result
            print(f"[+] FOUND (HTTP {status}): /{word} | Length: {length}")

print("\n[*] Scan finished.")
