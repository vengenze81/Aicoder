from rich.progress import track
import asyncio
import socket
import aiohttp
import ipaddress
import logging

logger = logging.getLogger("term_analyzer.tester")

class PortTester:
    def __init__(self, target: str, headers: dict = None, cookies: dict = None):
        self.target = target
        self.headers = headers or {}
        self.cookies = cookies or {}

    async def scan_ports(self, ports: list):
        open_ports = []
        for port in track(ports, description='[cyan]Testing ports...'):
            try:
                conn = asyncio.open_connection(self.target, port)
                reader, writer = await asyncio.wait_for(conn, timeout=1.5)
                banner = ""
                try:
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(1024), timeout=0.8)
                    banner = data.decode(errors="ignore").strip()
                except Exception:
                    pass
                writer.close()
                await writer.wait_closed()
                open_ports.append({"port": port, "banner": banner})
            except Exception:
                pass
        return open_ports

    async def discover_live_hosts(self, cidr: str):
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except Exception as e:
            logger.error(f"Invalid CIDR notation {cidr}: {e}")
            return []

        live_hosts = []
        common_ports = [80, 443, 8080, 22, 21]

        async def check_host(ip):
            for port in track(common_ports, description='[cyan]Testing common ports...'):
                try:
                    conn = asyncio.open_connection(str(ip), port)
                    _, writer = await asyncio.wait_for(conn, timeout=0.4)
                    writer.close()
                    await writer.wait_closed()
                    return str(ip)
                except Exception:
                    continue
            return None

        tasks = [check_host(ip) for ip in net.hosts()]
        results = await asyncio.gather(*tasks)
        live_hosts = [res for res in results if res is not None]
        return live_hosts

    async def audit_service(self, port: int, banner: str):
        vulnerable = False
        details = "Secure / N/A"
        if "Apache/2.4.49" in banner or "Apache/2.4.50" in banner:
            vulnerable = True
            details = "CVE-2021-41773 (Path Traversal)"
        elif "vsftpd 2.3.4" in banner:
            vulnerable = True
            details = "Backdoor Command Execution"
        return {"vulnerable": vulnerable, "details": details}

    async def fuzz_http_endpoints(self, base_url: str, paths: list, extensions: list = None, recursive: bool = False, exclude_statuses: list = None, exclude_sizes: list = None):
        extensions = extensions or []
        exclude_statuses = exclude_statuses or [404]
        exclude_sizes = exclude_sizes or []
        discovered = []
        seen_urls = set()

        async with aiohttp.ClientSession(headers=self.headers, cookies=self.cookies) as session:
            async def test_path(url):
                if url in seen_urls:
                    return
                seen_urls.add(url)
                try:
                    async with session.get(url, timeout=4, allow_redirects=True) as resp:
                        body = await resp.read()
                        status = resp.status
                        size = len(body)

                        # Apply exclusion filters
                        if status in exclude_statuses or size in exclude_sizes:
                            return

                        discovered.append({
                            "url": str(resp.url),
                            "status": status,
                            "size": size
                        })
                        if recursive and status in {200, 301, 302} and not url.endswith("/"):
                            sub_url = url + "/"
                            for p in paths:
                                await test_path(f"{sub_url}{p}")
                                for ext in extensions:
                                    await test_path(f"{sub_url}{p}.{ext}")
                except Exception:
                    pass

            tasks = []
            for path in paths:
                clean_path = path.lstrip("/")
                url = f"{base_url.rstrip('/')}/{clean_path}"
                tasks.append(test_path(url))
                for ext in extensions:
                    tasks.append(test_path(f"{url}.{ext}"))

            await asyncio.gather(*tasks)
        return discovered

    async def credential_spray_http(self, base_url: str, usernames: list, passwords: list, login_path: str = "/login"):
        successes = []
        async with aiohttp.ClientSession(headers=self.headers, cookies=self.cookies) as session:
            async def try_combo(username, password):
                try:
                    auth = aiohttp.BasicAuth(username, password)
                    target_url = f"{base_url.rstrip('/')}{login_path if login_path.startswith('/') else '/' + login_path}"
                    async with session.get(target_url, auth=auth, timeout=3) as resp:
                        if resp.status == 200 or ("dashboard" in str(resp.url).lower() and resp.status != 401):
                            return {"username": username, "password": password}
                except Exception:
                    pass
                return None

            tasks = [try_combo(u, p) for u in usernames for p in passwords]
            results = await asyncio.gather(*tasks)
            successes = [res for res in results if res is not None]
        return successes
