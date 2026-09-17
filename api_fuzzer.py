import asyncio
import httpx
import json

# Baseline WordPress and WooCommerce REST API common routes to fuzz
DEFAULT_API_ROUTES = [
    "/wp-json/",
    "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/posts",
    "/wp-json/wp/v2/pages",
    "/wp-json/wp/v2/comments",
    "/wp-json/wc/v3/",
    "/wp-json/wc/v3/products",
    "/wp-json/wc/v3/customers",
    "/wp-json/wc/v3/orders",
    "/wp-json/wc/v3/reports",
    "/wp-json/wp/v2/types",
    "/wp-json/wp/v2/statuses"
]

async def fuzz_api_endpoints(target_url, timeout=8.0, reporter=None):
    base = target_url.rstrip("/")
    print(f"[*] Starting REST API Endpoint Fuzzing against {base}")
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityAuditor/1.0",
        "Accept": "application/json, text/plain, */*"
    }
    
    print("-" * 80)
    print(f"{'ENDPOINT ROUTE':<35} | {'STATUS':<8} | {'EXPOSURE ASSESSMENT'}")
    print("-" * 80)
    
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        for route in DEFAULT_API_ROUTES:
            url = base + route
            try:
                response = await client.get(url, headers=headers)
                status = response.status_code
                content_type = response.headers.get("content-type", "")
                
                exposure_note = "Protected / Restricted"
                severity = "Info"
                
                if status == 200:
                    if "application/json" in content_type.lower():
                        exposure_note = "SUCCESS: Publicly accessible JSON endpoint"
                        severity = "Medium" if any(k in route for k in ["users", "customers", "orders"]) else "Low"
                    else:
                        exposure_note = "Responded with HTTP 200 (Non-JSON)"
                elif status == 401:
                    exposure_note = "Authentication Required (HTTP 401)"
                elif status == 403:
                    exposure_note = "Forbidden / Blocked (HTTP 403)"
                elif status == 404:
                    exposure_note = "Endpoint Not Found (HTTP 404)"
                else:
                    exposure_note = f"HTTP Status {status}"
                
                print(f"{route:<35} | {status:<8} | {exposure_note}")
                
                if reporter and status == 200 and "application/json" in content_type.lower():
                    reporter.add_finding(
                        title=f"Exposed REST API Route: {route}",
                        description=f"Endpoint returned HTTP 200 with JSON content. Status note: {exposure_note}",
                        severity=severity
                    )
            except Exception as e:
                print(f"{route:<35} | ERROR    | Connection failed: {e}")
                
    print("-" * 80)
    print("[*] REST API endpoint fuzzing completed.")
