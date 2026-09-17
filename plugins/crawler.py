import asyncio
import httpx
from html.parser import HTMLParser
from urllib.parse import urlparse, urljoin
from core.evasion import get_evasion_headers, apply_jitter

PLUGIN_META = {
    "name": "Recursive Async Web Crawler & Attack Surface Mapper",
    "flag": "--crawler",
    "description": "Spider target application to extract links, forms, and input parameters",
    "category": "recon"
}

class SimpleHTMLParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.links = set()
        self.forms = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == 'a' and 'href' in attrs_dict:
            href = attrs_dict['href']
            full_url = urljoin(self.base_url, href)
            # Stay within the same domain scope
            if urlparse(full_url).netloc == urlparse(self.base_url).netloc:
                self.links.add(full_url)
        elif tag == 'form':
            self.current_form = {
                "action": attrs_dict.get('action', ''),
                "method": attrs_dict.get('method', 'GET').upper(),
                "inputs": []
            }
            self.forms.append(self.current_form)
        elif tag == 'input' and self.current_form is not None:
            name = attrs_dict.get('name')
            if name:
                self.current_form["inputs"].append(name)

    def handle_endtag(self, tag):
        if tag == 'form':
            self.current_form = None

async def run(target_url, reporter=None):
    print(f"[*] Starting Recursive Async Web Crawler against: {target_url}")
    visited = set()
    to_visit = {target_url}
    discovered_links = set()
    all_forms = []

    headers = get_evasion_headers()
    async with httpx.AsyncClient(headers=headers, verify=False, follow_redirects=True) as client:
        # Shallow recursive spider (capped at 15 pages for speed and stability)
        count = 0
        while to_visit and count < 15:
            current_url = to_visit.pop()
            if current_url in visited:
                continue
            visited.add(current_url)
            count += 1

            try:
                await apply_jitter(0.1, 0.3)
                resp = await client.get(current_url, timeout=4.0)
                if resp.status_code == 200 and 'text/html' in resp.headers.get('content-type', ''):
                    parser = SimpleHTMLParser(current_url)
                    parser.feed(resp.text)
                    
                    for link in parser.links:
                        if link not in visited and len(to_visit) < 30:
                            discovered_links.add(link)
                            to_visit.add(link)
                    
                    for form in parser.forms:
                        all_forms.append({"page": current_url, "form": form})
            except Exception:
                pass

    print(f"[+] Crawl complete. Pages visited: {len(visited)} | Links discovered: {len(discovered_links)} | Forms found: {len(all_forms)}")
    
    findings = []
    for link in list(discovered_links)[:10]:
        print(f"    [Link] {link}")
        findings.append({"type": "link", "url": link})
        
    for f_item in all_forms:
        desc = f"Discovered HTML Form on {f_item['page']} [Method: {f_item['form']['method']}, Inputs: {f_item['form']['inputs']}]"
        print(f"    [Form] {desc}")
        findings.append({"type": "form", "page": f_item['page'], "inputs": f_item['form']['inputs']})
        if reporter:
            reporter.add_finding(
                module="Web Crawler",
                severity="LOW",
                description=desc,
                details=f_item
            )

    if reporter:
        reporter.add_section("Web Crawler Attack Surface Analysis", {
            "pages_visited": len(visited), 
            "total_links": len(discovered_links), 
            "forms_discovered": len(all_forms),
            "findings": findings
        })
