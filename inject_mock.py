from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    # 1. Inject a strict Content-Security-Policy header into the main page response
    if flow.response and ("medistore.se" in flow.request.pretty_url or "127.0.0.1:8000" in flow.request.pretty_url):
        # Only allow scripts from the origin itself ('self'), blocking external CDNs like helloretailcdn.com
        flow.response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self';"
        print("[+] [DEFENSE SIMULATION] Injected strict CSP header: script-src 'self'")

    # 2. Intercept the script request just in case it bypasses CSP
    if "helloretail.js" in flow.request.pretty_url and flow.response:
        flow.response.content = b"""
        console.warn("[RED TEAM] Payload reached browser despite CSP!");
        """
        print("[+] [RED TEAM] Payload returned by proxy.")
