import re

def extract_js_secrets_and_endpoints(js_content):
    endpoints = set()
    secrets = set()
    
    # Regex to find API routes and internal paths inside JS source code
    path_pattern = re.compile(r'["\'](/api/[^"\']+|/wp-json/[^"\']+|/[a-zA-Z0-9_\-/]+\.(?:php|json|js))["\']')
    matches = path_pattern.findall(js_content)
    for m in matches:
        endpoints.add(m)
        
    # Regex to scan for common hardcoded keys, tokens, or secrets
    secret_patterns = {
        "Potential API Key/Token": r'(?i)(?:api_key|apikey|secret|auth_token|bearer)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,64})["\']'
    }
    
    for label, pat in secret_patterns.items():
        sec_matches = re.findall(pat, js_content)
        for sm in sec_matches:
            secrets.add((label, sm))
            
    return list(endpoints), list(secrets)
