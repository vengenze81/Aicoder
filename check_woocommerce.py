import urllib.request
import json

url = "https://medistore.se/wp-json/wc/store/v1/products"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})

try:
    with urllib.request.urlopen(req) as resp:
        products = json.loads(resp.read().decode("utf-8"))
        print(f"[*] Found {len(products)} public product(s) via WooCommerce Store API:\n")
        for prod in products[:5]: # Show first 5 products
            print(f"Name: {prod.get('name')} | Price: {prod.get('prices', {}).get('price')} {prod.get('prices', {}).get('currency_code')} | ID: {prod.get('id')}")
except Exception as e:
    print(f"[-] Store API endpoint restricted or unavailable: {e}")
