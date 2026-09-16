import os
import glob
import yaml
import asyncio
import aiohttp
from rich.console import Console

console = Console()

def load_templates(template_path):
    """Loads a single YAML template file or all YAML files in a directory."""
    templates = []
    if os.path.isfile(template_path):
        paths = [template_path]
    elif os.path.isdir(template_path):
        paths = glob.glob(os.path.join(template_path, "*.yaml")) + glob.glob(os.path.join(template_path, "*.yml"))
    else:
        return []

    for p in paths:
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if data:
                    templates.append(data)
        except Exception as e:
            console.print(f"[bold red][!] Error loading template {p}: {e}[/bold red]")
    return templates

async def execute_template_request(session, target_base, request_def):
    """Executes a single HTTP request defined in a template."""
    method = request_def.get("method", "GET").upper()
    path = request_def.get("path", "/")
    
    # Ensure clean URL joining
    target_url = target_base.rstrip("/") + "/" + path.lstrip("/")
    
    headers = request_def.get("headers", {})
    body = request_def.get("body", None)
    
    request_kwargs = {"headers": headers, "ssl": False}
    if body:
        request_kwargs["data"] = body

    try:
        async with session.request(method, target_url, **request_kwargs) as response:
            text = await response.text()
            return response.status, text, target_url
    except Exception as e:
        return 0, str(e), target_url

def evaluate_matchers(status, text, matchers_def, condition="and"):
    """Evaluates status and word matchers against response data."""
    if not matchers_def:
        return True # Default to matched if no matchers specified
        
    results = []
    for matcher in matchers_def:
        m_type = matcher.get("type")
        if m_type == "status":
            allowed_statuses = matcher.get("status", [])
            results.append(status in allowed_statuses)
        elif m_type == "word":
            words = matcher.get("words", [])
            # Check if words are present in text
            word_matched = any(w in text for w in words)
            results.append(word_matched)
            
    if condition == "or":
        return any(results)
    return all(results) # default 'and'

async def run_template_scan(target_base, template_path, concurrency=10):
    """Scans a target using loaded YAML templates."""
    templates = load_templates(template_path)
    if not templates:
        console.print(f"[bold yellow][!] No valid templates found at: {template_path}[/bold yellow]")
        return []

    console.print(f"[bold cyan][*] Loaded {len(templates)} template(s). Starting scan against {target_base}...[/bold cyan]")
    
    semaphore = asyncio.Semaphore(concurrency)
    scan_results = []

    async with aiohttp.ClientSession() as session:
        for tpl in templates:
            tpl_id = tpl.get("id", "unknown-template")
            info = tpl.get("info", {})
            name = info.get("name", tpl_id)
            severity = info.get("severity", "info")
            
            requests = tpl.get("requests", [])
            for req in requests:
                async with semaphore:
                    status, text, url = await execute_template_request(session, target_base, req)
                    matchers = req.get("matchers", [])
                    condition = req.get("matchers-condition", "and")
                    
                    matched = evaluate_matchers(status, text, matchers, condition)
                    
                    scan_results.append({
                        "template_id": tpl_id,
                        "name": name,
                        "severity": severity,
                        "url": url,
                        "status_code": status,
                        "matched": matched,
                        "response_snippet": text[:150]
                    })
                    
    return scan_results
