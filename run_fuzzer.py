import asyncio
from tester import PortTester

async def main():
    tester = PortTester("127.0.0.1")
    with open("wordlist.txt") as f:
        paths = [line.strip() for line in f if line.strip()]
    
    print("[*] Fuzzing http://127.0.0.1:9090 for sensitive endpoints...")
    found = await tester.fuzz_http_endpoints("http://127.0.0.1:9090", paths)
    if not found:
        print("[-] No active endpoints matched from the wordlist (or service is down).")
    for res in found:
        print(f"[FOUND] Status: {res['status']} | Size: {res['size']} bytes | URL: {res['url']}")

if __name__ == "__main__":
    asyncio.run(main())
