import asyncio
import httpx
from urllib.parse import urlparse

PLUGIN_META = {
    "name": "Cloud Storage & S3 Bucket Enumerator",
    "flag": "--cloud-enum",
    "description": "Enumerate exposed cloud storage buckets (AWS S3, GCP, Azure Blob)",
    "category": "recon"
}

CLOUD_PATTERNS = [
    "{name}",
    "{name}-backup",
    "{name}-assets",
    "{name}-data",
    "{name}-bucket",
    "{name}-prod",
    "{name}-dev",
    "{name}-storage",
    "medistore",
    "medistore-backup",
    "medistore-assets",
    "medistore-aws",
    "medistore-storage"
]

async def check_bucket(client, provider_name, url, findings, reporter):
    try:
        resp = await client.get(url, timeout=4.0)
        if resp.status_code in [200, 403]:
            severity = "HIGH" if resp.status_code == 200 else "LOW"
            desc = f"[{provider_name}] Discovered cloud storage bucket: {url} [HTTP {resp.status_code}]"
            print(f"[+] [HTTP {resp.status_code}] {url}")
            findings.append({"provider": provider_name, "url": url, "status": resp.status_code, "severity": severity})
            if reporter:
                reporter.add_finding(
                    module="Cloud Storage Enum",
                    severity=severity,
                    description=desc,
                    details={"provider": provider_name, "url": url, "status_code": resp.status_code}
                )
    except Exception:
        pass

async def run(target_url, reporter=None):
    print(f"[*] Starting Cloud Storage & S3 Bucket Enumeration against target context...")
    
    parsed = urlparse(target_url)
    netloc = parsed.netloc or target_url
    base_name = netloc.split(".")[0]
    
    permutations = set()
    for pattern in CLOUD_PATTERNS:
        permutations.add(pattern.format(name=base_name))

    findings = []
    headers = {"User-Agent": "Mozilla/5.0 CloudEnumerator/3.0"}
    
    async with httpx.AsyncClient(headers=headers, verify=False, follow_redirects=True) as client:
        tasks = []
        for name in permutations:
            s3_url = f"https://{name}.s3.amazonaws.com"
            tasks.append(check_bucket(client, "AWS S3", s3_url, findings, reporter))
            
            gcp_url = f"https://storage.googleapis.com/{name}"
            tasks.append(check_bucket(client, "Google Cloud", gcp_url, findings, reporter))
            
            azure_url = f"https://{name}.blob.core.windows.net/"
            tasks.append(check_bucket(client, "Azure Blob", azure_url, findings, reporter))

        await asyncio.gather(*tasks)

    print(f"[*] Cloud bucket enumeration completed. Active cloud storage entities found: {len(findings)}")
    if reporter:
        reporter.add_section("Cloud Storage Enumeration Analysis", {"permutations_checked": len(permutations) * 3, "findings_count": len(findings), "findings": findings})
