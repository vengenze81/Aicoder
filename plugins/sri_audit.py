import asyncio
import httpx
from html.parser import HTMLParser
from urllib.parse import urlparse, urljoin
from core.evasion import get_evasion_headers, apply_jitter

PLUGIN_META = {
    "name": "Subresource Integrity (SRI) Auditor",
    "flag": "--sri-audit",
    "description": "Check if external scripts and stylesheets loaded from CDNs lack integrity hashes",
    "category": "recon"
}

class SRIParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.external_assets = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        target_attr = None
        if tag == 'script' and 'src' in attrs_dict:
            target_attr = 'src'
        elif tag == 'link' and attrs_dict.get('rel', '').lower() == 'stylesheet' and 'href' in attrs_dict:
            target_attr = 'href'

        if target_attr:
            url = attrs_dict[target_attr]
            full_url = urljoin(self.base_url, url)
            parsed_base = urlparse(self.base_url)
            parsed_asset = urlparse(full_url)
            
            # Check if asset belongs to an external domain / CDN
            is_external = parsed_asset.netloc and parsed_asset.netloc != parsed_base.netloc
            has_integrity = 'integrity' in attrs_dict
            
            if is_external:
                self.external_assets.append({
                    "tag": tag,
                    "url": full_url,
                    "has_integrity": has_integrity,
                    "attrs": attrs_dict
                })

async def run(target_url, reporter=None):
    print(f"[*] Starting Subresource Integrity (SRI) Audit against: {target_url}")
    findings = []
    headers = get_evasion_headers()

    async with httpx.AsyncClient(headers=headers, verify=False, follow_redirects=True) as client:
        try:
            await apply_jitter(0.1, 0.3)
            resp = await client.get(target_url, timeout=5.0)
            if resp.status_code == 200:
                parser = SRIParser(target_url)
                parser.feed(resp.text)
                
                print(f"[+] Found {len(parser.external_assets)} external asset(s) loaded from CDNs/remote domains.")

                for asset in parser.external_assets:
                    if not asset["has_integrity"]:
                        severity = "MEDIUM" if asset["tag"] == "script" else "LOW"
                        desc = f"External {asset['tag']} loaded without SRI integrity hash: {asset['url']}"
                        print(f"[!] [{severity}] {desc}")
                        findings.append({
                            "tag": asset["tag"],
                            "url": asset["url"],
                            "severity": severity
                        })
                        if reporter:
                            reporter.add_finding(
                                module="SRI Auditor",
                                severity=severity,
                                description=desc,
                                details=asset
                            )
                    else:
                        print(f"[+] [OK] {asset['tag']} has valid SRI integrity hash: {asset['url']}")
        except Exception as e:
            print(f"[-] SRI audit failed: {e}")

    print(f"[*] SRI audit completed. Missing integrity hashes flagged: {len(findings)}")
    if reporter:
        reporter.add_section("Subresource Integrity (SRI) Analysis", {"findings_count": len(findings), "findings": findings})
