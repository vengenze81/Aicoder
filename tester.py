import asyncio
import socket
import ipaddress
import urllib.request
import urllib.error
import base64
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

    async def audit_service(self, port: int, banner: str) -> dict:
        """Perform lightweight, unauthenticated or default credential checks on specific services."""
        loop = asyncio.get_running_loop()

        def _audit_sync():
            try:
                # Redis check (6379)
                if port == 6379 or "redis" in banner.lower():
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2.0)
                    s.connect((self.target, port))
                    s.sendall(b"PING\r\n")
                    resp = s.recv(1024).decode("utf-8", errors="ignore")
                    s.close()
                    if "PONG" in resp:
                        return {"vulnerable": True, "details": "Redis server allows UNAUTHENTICATED access (PONG received)."}

                # FTP check (21)
                elif port == 21 or "ftp" in banner.lower():
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3.0)
                    s.connect((self.target, port))
                    s.recv(1024)
                    s.sendall(b"USER anonymous\r\n")
                    s.recv(1024)
                    s.sendall(b"PASS anonymous\r\n")
                    r2 = s.recv(1024).decode("utf-8", errors="ignore")
                    s.close()
                    if "230" in r2 or "Login successful" in r2:
                        return {"vulnerable": True, "details": "FTP server allows ANONYMOUS login."}

                # HTTP / Web checks for default creds (Tomcat, Jenkins, etc.)
                elif port in {80, 443, 8080, 8443, 8000, 5000, 9090}:
                    scheme = "https" if port in {443, 8443} else "http"
                    base_url = f"{scheme}://{self.target}:{port}"
                    
                    try:
                        req = urllib.request.Request(base_url, headers={"User-Agent": "Mozilla/5.0"})
                        with urllib.request.urlopen(req, timeout=3) as resp:
                            if resp.status == 200:
                                html = resp.read().decode("utf-8", errors="ignore").lower()
                                if "jenkins" in html or "tomcat" in html or "dashboard" in html:
                                    return {"vulnerable": True, "details": f"Web service at {base_url} is accessible without authentication."}
                    except Exception:
                        pass

                    default_creds = [("admin", "admin"), ("admin", "password"), ("root", "root"), ("tomcat", "tomcat")]
                    for user, pwd in default_creds:
                        credentials = f"{user}:{pwd}"
                        encoded_creds = base64.b64encode(credentials.encode()).decode()
                        for path in ["manager/html", "jenkins/login", ""]:
                            try:
                                url = f"{base_url.rstrip('/')}/{path}"
                                req = urllib.request.Request(url, headers={
                                    "Authorization": f"Basic {encoded_creds}",
                                    "User-Agent": "Mozilla/5.0"
                                })
                                with urllib.request.urlopen(req, timeout=3) as resp:
                                    if resp.status == 200:
                                        return {"vulnerable": True, "details": f"Default credentials ({user}:{pwd}) accepted at {url}!"}
                            except Exception:
                                pass
            except Exception:
                pass
            return {"vulnerable": False, "details": ""}

        return await loop.run_in_executor(None, _audit_sync)


    async def credential_spray_http(self, base_url: str, usernames: list[str], password: str) -> list[dict]:
        """Perform an asynchronous credential spray (one password across multiple usernames) via HTTP Basic Auth."""
        async def check_creds(username: str):
            loop = asyncio.get_running_loop()
            def _sync_spray():
                credentials = f"{username}:{password}"
                encoded_creds = base64.b64encode(credentials.encode()).decode()
                try:
                    req = urllib.request.Request(
                        f"{base_url.rstrip('/')}/",
                        headers={
                            "Authorization": f"Basic {encoded_creds}",
                            "User-Agent": "Mozilla/5.0 (TermAnalyzer-Sprayer)"
                        }
                    )
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        if resp.status == 200:
                            return {"username": username, "password": password, "status": resp.status, "success": True}
                except urllib.error.HTTPError as e:
                    if e.code == 200:
                        return {"username": username, "password": password, "status": e.code, "success": True}
                except Exception:
                    pass
                return None

            return await loop.run_in_executor(None, _sync_spray)

        tasks = [check_creds(user) for user in usernames]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]

def discover_local_interfaces() -> list[str]:
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
