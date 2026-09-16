import asyncio
import socket
import urllib.request
import urllib.error
import base64

class PortTester:
    def __init__(self, target: str):
        self.target = target

    def test_port(self, port: int) -> dict:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            result = s.connect_ex((self.target, port))
            s.close()
            if result == 0:
                banner = ""
                try:
                    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s2.settimeout(1.0)
                    s2.connect((self.target, port))
                    s2.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s2.recv(1024).decode("utf-8", errors="ignore")
                    s2.close()
                except Exception:
                    pass
                return {"port": port, "status": "open", "banner": banner.strip()}
            return {"port": port, "status": "closed", "banner": ""}
        except Exception:
            return {"port": port, "status": "filtered", "banner": ""}

    async def scan_ports(self, ports: list[int]) -> list[dict]:
        loop = asyncio.get_running_loop()
        tasks = [loop.run_in_executor(None, self.test_port, p) for p in ports]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r["status"] == "open"]

    async def fuzz_http_endpoints(self, base_url: str, paths: list[str], extensions: list[str] = None, recursive: bool = False, max_depth: int = 2, current_depth: int = 1) -> list[dict]:
        extensions = extensions or []
        found_results = []
        checked_urls = set()

        async def check_path(url: str):
            if url in checked_urls:
                return None
            checked_urls.add(url)
            
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

        target_urls = []
        for path in paths:
            clean_path = path.strip("/")
            if not clean_path:
                continue
            target_urls.append(f"{base_url.rstrip('/')}/{clean_path}")
            if "." not in clean_path:
                for ext in extensions:
                    clean_ext = ext.lstrip(".")
                    target_urls.append(f"{base_url.rstrip('/')}/{clean_path}.{clean_ext}")

        tasks = [check_path(u) for u in target_urls]
        responses = await asyncio.gather(*tasks)
        valid_hits = [r for r in responses if r is not None]
        found_results.extend(valid_hits)

        if recursive and current_depth < max_depth:
            for hit in valid_hits:
                if hit["status"] in [200, 301, 302]:
                    hit_url = hit["url"]
                    sub_paths = ["admin", "api", "config", "status", "v1", "test"]
                    sub_results = await self.fuzz_http_endpoints(hit_url, sub_paths, extensions=extensions, recursive=True, max_depth=max_depth, current_depth=current_depth + 1)
                    found_results.extend(sub_results)

        return found_results

    async def audit_service(self, port: int, banner: str) -> dict:
        """Perform lightweight, unauthenticated or default credential checks on specific services."""
        loop = asyncio.get_running_loop()

        def _audit_sync():
            try:
                if port == 6379 or "redis" in banner.lower():
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2.0)
                    s.connect((self.target, port))
                    s.sendall(b"PING\r\n")
                    resp = s.recv(1024).decode("utf-8", errors="ignore")
                    s.close()
                    if "PONG" in resp:
                        return {"vulnerable": True, "details": "Redis server allows UNAUTHENTICATED access (PONG received)."}

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
