from __future__ import annotations
import unittest
from tester import PortTester, ServiceInfo

class TestTester(unittest.TestCase):
    def test_service_info_to_dict(self):
        service = ServiceInfo(port=80, banner="HTTP/1.0 200 OK", status="open", version="HTTP 1.0")
        d = service.to_dict()
        self.assertEqual(d["port"], 80)
        self.assertEqual(d["status"], "open")
        self.assertEqual(d["banner"], "HTTP/1.0 200 OK")

    def test_version_extraction(self):
        tester = PortTester("127.0.0.1")
        
        # Test Apache pattern
        ver1 = tester._extract_version("Server: Apache/2.4.49 (Unix)")
        self.assertEqual(ver1, "Apache 2.4.49")

        # Test SSH pattern
        ver2 = tester._extract_version("SSH-2.0-OpenSSH_8.2p1 Ubuntu")
        self.assertEqual(ver2, "SSH 2.0")

        # Test non-matching banner
        ver3 = tester._extract_version("UnknownServiceBanner")
        self.assertIsNone(ver3)

if __name__ == "__main__":
    unittest.main()

import asyncio

def test_async_port_scanner():
    from tester import PortTester
    tester = PortTester("127.0.0.1", timeout=0.5)
    
    async def run_scan():
        # Scan a couple of ports concurrently
        return await tester.scan_ports([80, 443])
        
    results = asyncio.run(run_scan())
    assert isinstance(results, list)
    assert len(results) == 2

import asyncio

def test_async_port_scanner():
    from tester import PortTester
    tester = PortTester("127.0.0.1", timeout=0.5)
    
    async def run_scan():
        # Scan a couple of ports concurrently
        return await tester.scan_ports([80, 443])
        
    results = asyncio.run(run_scan())
    assert isinstance(results, list)
    assert len(results) == 2
