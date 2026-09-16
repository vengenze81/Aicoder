from __future__ import annotations
import asyncio
import re
import socket
from dataclasses import asdict, dataclass
from typing import List, Optional

@dataclass(slots=True)
class ServiceInfo:
    port: int
    banner: Optional[str] = None
    status: str = "closed"
    version: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

class PortTester:
    def __init__(self, target: str, timeout: float = 2.0) -> None:
        self.target = target
        self.timeout = timeout

    def grab_banner(self, port: int) -> ServiceInfo:
        """Synchronously probe a port and grab its banner/version info (backward compatible)."""
        service = ServiceInfo(port=port)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((self.target, port))
                service.status = "open"

                probe = self._get_probe_payload(port)
                if probe:
                    s.sendall(probe)

                banner_data = s.recv(1024)
                if banner_data:
                    banner_str = banner_data.decode("utf-8", errors="ignore").strip()
                    service.banner = banner_str
                    service.version = self._extract_version(banner_str)
        except (socket.timeout, ConnectionRefusedError, OSError):
            service.status = "closed"
        return service

    async def agrab_banner(self, port: int) -> ServiceInfo:
        """Asynchronously probe a port and grab its banner/version info."""
        service = ServiceInfo(port=port)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, port),
                timeout=self.timeout
            )
            service.status = "open"

            probe = self._get_probe_payload(port)
            if probe:
                writer.write(probe)
                await writer.drain()

            try:
                banner_data = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                if banner_data:
                    banner_str = banner_data.decode("utf-8", errors="ignore").strip()
                    service.banner = banner_str
                    service.version = self._extract_version(banner_str)
            except asyncio.TimeoutError:
                pass

            writer.close()
            await writer.wait_closed()
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, Exception):
            service.status = "closed"
        return service

    async def scan_ports(self, ports: List[int]) -> List[ServiceInfo]:
        """Concurrently scan multiple ports using asyncio."""
        tasks = [self.agrab_banner(port) for port in ports]
        return await asyncio.gather(*tasks)

    def _get_probe_payload(self, port: int) -> bytes:
        """Return custom probe payloads to force services to reveal themselves."""
        if port in (80, 443, 8080, 8443):
            return b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        elif port in (21, 22, 25):
            return b"\r\n"
        return b""

    def _extract_version(self, banner: str) -> Optional[str]:
        """Extract software version strings using regular expressions."""
        if banner.startswith("SSH-"):
            parts = banner.split("-")
            if len(parts) >= 2:
                return f"SSH {parts[1]}"

        match = re.search(r"([a-zA-Z\-_]+)[/\s_]([\d\.]+[\w\-]*)", banner)
        if match:
            return f"{match.group(1)} {match.group(2)}"
        return None

    async def scan_subnet(self, subnet_str: str, ports: list[int]) -> list[ServiceInfo]:
        """Concurrently scan an entire CIDR subnet across specified ports."""
        import ipaddress
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

def discover_local_interfaces() -> list[str]:
    """Identify active local IP addresses and local subnet ranges for internal pivoting."""
    import socket
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

