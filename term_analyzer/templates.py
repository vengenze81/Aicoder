import os
import yaml
import asyncio
import aiohttp
from aiohttp_socks import ProxyConnector
from rich.console import Console

console = Console()

def load_template(template_path):
    """Loads a single YAML template or all templates in a directory."""
    templates = []
    if os.path.isdir(template_path):
        for root, _, files in os.walk(template_path):
            for file in files:
                if file.endswith((".yaml", ".yml")):
                    full_path = os.path.join(root, file)
                    templates.append(load_single_yaml(full_path))
    elif os.path.isfile(template_path):
        templates.append(load_single_yaml(template_path))
    return [t for t in templates if t]

def load_single_yaml(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception as e:
        console.print(f"[bold red][!] Error loading template {path}: {e}[/bold red]")
        return None

def match_rules(status, text, match_config):
    """Evaluates status codes, match strings, regex patterns, and negative rules."""
    import re
    
    # 1. Status check
    statuses = match_config.get("status", [])
    if status not in statuses:
        return False
        
    # 2. String matching (all must match)
    match_strings = match_config.get("match", [])
    for s in match_strings:
        if s not in text:
            return False
            
    # 3. Regex matching
    match_regexes = match_config.get("regex", [])
    for rx in match_regexes:
        if not re.search(rx, text):
            return False
            
    # 4. Negative matching (none of these should be present if negative: true)
    negative_rules = match_config.get("negative", [])
    for neg in negative_rules:
        if neg in text:
            return False
            
    return True

async def execute_template_request(session, target_base, template):
    """Executes requests defined in a template against a target URL."""
    results = []
    path = template.get("path", "/")
    method = template.get("method", "GET").upper()
    match_config = template.get("matchers", {})
    name = template.get("name", "Unknown Check")
    severity = template.get("severity", "info")
    
    url = target_base.rstrip("/") + "/" + path.lstrip("/")
    
    try:
        async with session.request(method, url, timeout=10) as response:
            status = response.status
            text = await response.text()
            matched = match_rules(status, text, match_config)
            
            results.append({
                "name": name,
                "severity": severity,
                "url": url,
                "status_code": status,
                "response_snippet": text,
                "matched": matched
            })
    except Exception as e:
        results.append({
            "name": name,
            "severity": severity,
            "url": url,
            "status_code": 0,
            "response_snippet": str(e),
            "matched": False
        })
        
    return results

async def run_template_scan(target_base, template_path, concurrency=10, proxy=None):
    """Asynchronously runs loaded vulnerability templates against a target with optional proxy."""
    templates = load_template(template_path)
    if not templates:
        console.print(f"[bold red][!] No valid templates found at {template_path}[/bold red]")
        return []

    connector = ProxyConnector.from_url(proxy) if proxy else None
    
    semaphore = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for t in templates:
            async with semaphore:
                tasks.append(execute_template_request(session, target_base, t))
        
        nested_results = await asyncio.gather(*tasks)
        flattened = [item for sublist in nested_results for item in sublist]
        return flattened
