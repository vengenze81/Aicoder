import re
from urllib.parse import urlparse, urljoin

def extract_internal_links(base_url, html_content):
    discovered_paths = set()
    parsed_base = urlparse(base_url)
    
    href_matches = re.findall(r'href=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
    
    for href in href_matches:
        full_url = urljoin(base_url, href)
        parsed_url = urlparse(full_url)
        
        # Ensure it belongs to the target domain and has no query parameters (prevents filter loops)
        if parsed_url.netloc == parsed_base.netloc and not parsed_url.query:
            path = parsed_url.path
            if not path or path == "/":
                continue
                
            # Filter out static media/assets and infinite pagination/archive traps
            ignored_patterns = (
                '.png', '.jpg', '.jpeg', '.gif', '.css', '.js', 
                '.ico', '.pdf', '.svg', '.woff', '.woff2', '.webp', '.zip',
                '/page/', '/tag/', '/author/', '/comment-page-'
            ]
            
            if not any(pat in path.lower() for pat in ignored_patterns):
                discovered_paths.add(path)
                
    return list(discovered_paths)
