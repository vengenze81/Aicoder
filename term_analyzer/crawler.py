import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from rich.console import Console
from term_analyzer.secrets_finder import extract_secrets

console = Console()

async def crawl_target(target_url, max_depth=2, concurrency=10):
    """Recursively crawls a target URL to discover links, forms, and sensitive data."""
    parsed_base = urlparse(target_url)
    base_netloc = parsed_base.netloc
    
    visited = set()
    queue = asyncio.Queue()
    await queue.put((target_url, 0))
    
    semaphore = asyncio.Semaphore(concurrency)
    discovered_endpoints = []
    discovered_forms = []

    console.print(f"[bold cyan][*] Starting recursive crawl on {target_url} (Max Depth: {max_depth})[/bold cyan]")

    async with aiohttp.ClientSession() as session:
        while not queue.empty():
            current_url, depth = await queue.get()
            
            if current_url in visited or depth > max_depth:
                queue.task_done()
                continue
                
            visited.add(current_url)
            
            async with semaphore:
                try:
                    async with session.get(current_url, timeout=10) as response:
                        if response.status != 200:
                            queue.task_done()
                            continue
                            
                        html = await response.text()
                        content_type = response.headers.get("Content-Type", "")
                        
                        if "text/html" not in content_type:
                            queue.task_done()
                            continue

                        # Run secret extraction on crawled page
                        secrets = extract_secrets(html)
                        if secrets:
                            for s in secrets:
                                console.print(f"[bold red]⚠️ CRAWL LEAK FOUND [{current_url}]: {s['secret_type']} -> {s['matches']}[/bold red]")

                        discovered_endpoints.append({
                            "url": current_url,
                            "status": response.status,
                            "depth": depth,
                            "secrets": secrets
                        })

                        # Parse HTML for links and forms
                        soup = BeautifulSoup(html, "html.parser")
                        
                        # Extract Forms
                        for form in soup.find_all("form"):
                            action = form.get("action", "")
                            method = form.get("method", "get").upper()
                            form_url = urljoin(current_url, action)
                            inputs = [input_tag.get("name") for input_tag in form.find_all("input") if input_tag.get("name")]
                            discovered_forms.append({
                                "page": current_url,
                                "action": form_url,
                                "method": method,
                                "inputs": inputs
                            })

                        # Extract Links
                        if depth < max_depth:
                            for link in soup.find_all("a", href=True):
                                href = link["href"]
                                full_url = urljoin(current_url, href)
                                parsed_link = urlparse(full_url)
                                
                                # Restrict to same domain and HTTP/HTTPS
                                if parsed_link.netloc == base_netloc and parsed_link.scheme in ["http", "https"]:
                                    # Strip fragments/query duplication for basic tracking
                                    clean_url = f"{parsed_link.scheme}://{parsed_link.netloc}{parsed_link.path}"
                                    if clean_url not in visited:
                                        await queue.put((full_url, depth + 1))
                                        
                except Exception as e:
                    pass
                finally:
                    queue.task_done()

    console.print(f"[bold green][+] Crawl complete: Found {len(discovered_endpoints)} unique pages and {len(discovered_forms)} HTML forms.[/bold green]")
    return discovered_endpoints, discovered_forms
