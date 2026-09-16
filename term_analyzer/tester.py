import asyncio
import socket
import aiohttp
import urllib.parse
import ipaddress
import logging

logger = logging.getLogger("term_analyzer.tester")

def discover_local_interfaces():
    return []

class PortTester:
    def __init__(self, target: str):
        self.target = target

    async def scan_ports(self, ports: list[int], timeout: float = 1.0) -> list[dict]:
        open_ports = []
        async def check_port(port):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target, port), timeout=timeout
                )
                banner = ""
                try:
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(1024), timeout=0.5)
                    banner = data.decode('utf-8', errors='ignore').strip()
                except Exception:
                    pass
                writer.close()
                await writer.wait_closed()
                open_ports.append({"port": port, "status": "open", "banner": banner})
            except Exception:
                pass

        await asyncio.gather(*(check_port(p) for p in ports))
        return open_ports

    async def audit_service(self, port: int, banner: str) -> dict:
        vulnerable = False
        if "Apache/2.4.49" in banner or "vulnerable" in banner.lower():
            vulnerable = True
        return {"vulnerable": vulnerable}

    async def fuzz_http_endpoints(self, base_url: str, paths: list[str], extensions: list[str] = None, recursive: bool = False) -> list[dict]:
        extensions = extensions or []
        discovered = []
        visited = set()

        async def test_path(session, url):
            if url in visited:
                return
            visited.add(url)
            try:
                async with session.get(url, allow_redirects=False, timeout=3) as resp:
                    if resp.status in {200, 301, 302, 403, 401}:
                        body = await resp.read()
                        discovered.append({
                            "url": url,
                            "status": resp.status,
                            "size": len(body)
                        })
                        if recursive and resp.status in {200, 301, 302} and not url.endswith(tuple(extensions)) and not "." in url.split("/")[-1]:
                            sub_paths = ["admin", "api", "config", "backup", "v1", "test", "settings", "data"]
                            for sp in sub_paths:
                                clean_base = url.rstrip('/')
                                sub_url = f"{clean_base}/{sp}"
                                await test_path(session, sub_url)
                                for ext in extensions:
                                    await test_path(session, f"{sub_url}.{ext}")
            except Exception:
                pass

        async with aiohttp.ClientSession() as session:
            tasks = []
            for path in paths:
                clean_path = path.lstrip('/')
                target_url = f"{base_url.rstrip('/')}/{clean_path}"
                tasks.append(test_path(session, target_url))
                for ext in extensions:
                    tasks.append(test_path(session, f"{target_url}.{ext}"))
            if tasks:
                await asyncio.gather(*tasks)
        return discovered

    async def credential_spray_http(self, base_url: str, usernames: list[str], password: str) -> list[dict]:
        successes = []
        async with aiohttp.ClientSession() as session:
            for username in usernames:
                try:
                    auth = aiohttp.BasicAuth(username, password)
                    async with session.get(f"{base_url}/login", auth=auth, timeout=3) as resp:
                        if resp.status == 200:
                            successes.append({"username": username, "password": password})
                except Exception:
                    pass
        return successes

    async def discover_live_hosts(self, cidr: str, probe_ports: list[int] = [80, 443, 8080, 22]) -> list[str]:
        network = ipaddress.ip_network(cidr, strict=False)
        ips = list(network.hosts()) if network.num_addresses > 2 else [network.network_address]
        
        async def check_host(ip_str):
            for port in probe_ports:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(str(ip_str), port), timeout=0.6
                    )
                    writer.close()
                    await writer.wait_closed()
                    return str(ip_str)
                except Exception:
                    continue
            return None

        tasks = [check_host(ip) for ip in ips]
        results = await asyncio.gather(*tasks)
        return [ip for ip in results if ip is not None]
