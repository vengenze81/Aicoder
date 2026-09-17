import asyncio
import httpx
import re
from html.parser import HTMLParser
from urllib.parse import urlparse, urljoin
from core.evasion import get_evasion_headers, apply_jitter

PLUGIN_META = {
    "name": "JavaScript Secret & Endpoint Finder",
    "flag": "--js-audit",
    "description": "Extract and scan JavaScript files for hardcoded secrets, API keys, and endpoints",
    "category": "recon"
}

# Regex patterns for high-risk secrets and endpoints
SECRET_PATTERNS = {
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Generic Bearer Token": r"bearer\s+[a-zA-Z0-9_\-\.]{20,}",
    "Private Key Block": r"-----BEGIN PRIVATE KEY-----",
    "Internal Endpoint Route": r"['\"]/api/v[0-9]/[a-zA-Z0-9_\-/]+['\"]"
}

class JSLinkParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.js_links = set()

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == 'script' and 'src' in attrs_dict:
            src = attrs_dict['src']
            full_url = urljoin(self.base_url, src)
            if urlparse(full_url).netloc == urlparse(self.base_url).netloc:
                self.js_links.add(full_url)

async def scan_js_file(client, js_url, findings, reporter):
    try:
        await apply_jitter(0.1, 0.3)
        headers = get_evasion_headers()
        resp = await client.get(js_url, headers=headers, timeout=5.0)
        
        if resp.status_code == 200:
            content = resp.text
            for secret_name, pattern in SECRET_PATTERNS.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    severity = "HIGH" if "Key" in secret_name or "Private" in secret_name else "MEDIUM"
                    desc = f"Detected potential {secret_name} in JS asset: {js_url}"
                    print(f"[!] [{severity}] {desc}")
                    findings.append({
                        "js_url": js_url,
                        "type": secret_name,
                        "matches_count": len(matches),
                        "severity": severity
                    })
                    if reporter:
                        reporter.add_finding(
                            module="JS Secret Finder",
                            severity=severity,
                            description=desc,
                            details={"js_url": js_url, "secret_type": secret_name, "sample": str(matches[:2])}
                        )
    except Exception:
        pass

async def run(target_url, reporter=None):
    print(f"[*] Starting JavaScript Secret & Endpoint Finder against: {target_url}")
    js_files = set()
    headers = get_evasion_headers()
    
    async with httpx.AsyncClient(headers=headers, verify=False, follow_redirects=True) as client:
        try:
            resp = await client.get(target_url, timeout=5.0)
            if resp.status_code == 200:
                parser = JSLinkParser(target_url)
                parser.feed(resp.text)
                js_files = parser.js_links
        except Exception as e:
            print(f"[-] Failed to fetch root page for JS extraction: {e}")

    print(f"[*] Discovered {len(js_files)} JavaScript files. Scanning content for credentials...")
    findings = []
    
    if js_files:
        async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
            tasks = [scan_js_file(client, js_url, findings, reporter) for js_url in js_files]
            await asyncio.gather(*tasks)

    print(f"[*] JavaScript audit completed. Potential exposures flagged: {len(findings)}")
    if reporter:
        reporter.add_section("JavaScript Secret Analysis", {"js_files_scanned": len(js_files), "findings_count": len(findings), "findings": findings})
