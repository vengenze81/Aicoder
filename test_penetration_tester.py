import unittest
from penetration_tester import PenetrationTester, ServiceInfo

class TestPenetrationTester(unittest.TestCase):
    def test_service_info_to_dict(self):
        service = ServiceInfo(port=80, banner="HTTP/1.0 200 OK", status="open")
        d = service.to_dict()
        self.assertEqual(d, {"port": 80, "status": "open", "banner": "HTTP/1.0 200 OK"})

if __name__ == "__main__":
    unittest.main()