import asyncio
import json
import yaml
import aiohttp
from rich.console import Console
from term_analyzer.secrets_finder import extract_secrets

console = Console()

def load_openapi_spec(spec_path):
    """Loads and parses an OpenAPI/Swagger spec from JSON or YAML."""
    try:
        with open(spec_path, "r", encoding="utf-8") as f:
            content = f.read()
            if spec_path.endswith(".json"):
                return json.loads(content)
            else:
                return yaml.safe_load(content)
    except Exception as e:
        console.print(f"[bold red][!] Error loading OpenAPI spec {spec_path}: {e}[/bold red]")
        return None

async def test_api_endpoint(session, base_url, path, method, parameters, custom_headers, custom_cookies, semaphore):
    """Probes an individual API endpoint with test fuzzing."""
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    async with semaphore:
        try:
            async with session.request(method.upper(), url, headers=custom_headers, cookies=custom_cookies, timeout=10) as response:
                status = response.status
                text = await response.text()
                secrets = extract_secrets(text)
                return path, method, status, len(text), text[:150], secrets
        except Exception as e:
            return path, method, 0, 0, str(e), []

async def run_openapi_scan(base_url, spec_path, custom_headers=None, custom_cookies=None, concurrency=10):
    spec = load_openapi_spec(spec_path)
    if not spec:
        return []

    paths = spec.get("paths", {})
    console.print(f"[bold cyan][*] Loaded OpenAPI spec: Found {len(paths)} endpoint paths to assess against {base_url}[/bold cyan]")

    semaphore = asyncio.Semaphore(concurrency)
    custom_headers = custom_headers or {}
    custom_cookies = custom_cookies or {}
    results = []

    async with aiohttp.ClientSession() as session:
        tasks = []
        for path, methods in paths.items():
            for method in methods.keys():
                if method.lower() in ["get", "post", "put", "delete", "patch"]:
                    tasks.append(
                        test_api_endpoint(session, base_url, path, method, methods[method], custom_headers, custom_cookies, semaphore)
                    )
        
        responses = await asyncio.gather(*tasks)

    for path, method, status, length, text, secrets in responses:
        color = "green" if status < 400 else ("yellow" if status < 500 else "red")
        console.print(f"[{color}][API] {method.upper()} {path} -> Status: {status} | Length: {length}[/{color}]")
        if secrets:
            for s in secrets:
                console.print(f"    [bold red]⚠️ SENSITIVE DATA LEAK: {s['secret_type']} -> {s['matches']}[/bold red]")
                
        results.append({
            "payloads": [f"{method.upper()} {path}"],
            "status_code": status,
            "response_length": length,
            "response_snippet": text,
            "extracted_secrets": secrets
        })

    return results
