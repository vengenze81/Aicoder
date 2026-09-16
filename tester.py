import asyncio
import socket
import ipaddress
import urllib.request
import urllib.error
from dataclasses import dataclass

@dataclass
class ServiceInfo:
    host: str
    port: int
    banner: str
    status: str

class PortTester:
    def __init__(self, target: str, timeout: float = 2.0):
        self.target = target
        self.timeout = timeout

    async def agrab_banner(self, port: int) -> ServiceInfo:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, port),
                timeout=self.timeout
            )
            banner = ""
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                banner = data.decode("utf-8", errors="ignore").strip()
            except asyncio.TimeoutError:
                pass

            writer.close()
            await writer.wait_closed()
            return ServiceInfo(host=self.target, port=port, banner=banner, status="open")
        except Exception:
            return ServiceInfo(host=self.target, port=port, banner="", status="closed")

    async def scan_ports(self, ports: list[int]) -> list[ServiceInfo]:
        tasks = [self.agrab_banner(port) for port in ports]
        results = await asyncio.gather(*tasks)
        return [res for res in results if res.status == "open"]

    async def scan_subnet(self, subnet_str: str, ports: list[int]) -> list[ServiceInfo]:
        """Concurrently scan an entire CIDR subnet across specified ports."""
        try:
            network = ipaddress.ip_network(subnet_str, strict=False)
            hosts = [str(ip) for ip in network.hosts()]
            if not hosts:
                hosts = [str(network.network_address)]
        except ValueError:
            hosts = [subnet_str]

        tasks = []
        for host in hosts:
            for port in ports:
                sub_tester = PortTester(target=host, timeout=self.timeout)
                tasks.append(sub_tester.agrab_banner(port))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        valid_services = [res for res in results if isinstance(res, ServiceInfo) and res.status == "open"]
        return valid_services

    async def fuzz_http_endpoints(self, base_url: str, paths: list[str]) -> list[dict]:
        """Asynchronously fuzz a target web base URL for sensitive directories or endpoints."""
        async def check_path(path: str):
            url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
            loop = asyncio.get_running_loop()
            
            def _sync_request():
                try:
                    req = urllib.request.Request(
                        url,
                        headers={"User-Agent": "Mozilla/5.0 (TermAnalyzer-Recon)"}
                    )
                    with urllib.request.urlopen(req, timeout=3) as response:
                        return response.status, len(response.read())
                except urllib.error.HTTPError as e:
                    return e.code, 0
                except Exception:
                    return None, 0

            status, size = await loop.run_in_executor(None, _sync_request)
            if status and status in [200, 301, 302, 401, 403]:
                return {"url": url, "status": status, "size": size}
            return None

        tasks = [check_path(path) for path in paths]
        responses = await asyncio.gather(*tasks)
        return [r for r in responses if r is not None]

def discover_local_interfaces() -> list[str]:
    """Identify active local IP addresses and local subnet ranges for internal pivoting."""
    local_ips = []
    try:
        hostname = socket.gethostname()
        local_ips.append(socket.gethostbyname(hostname))
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ips.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return list(set(local_ips))
