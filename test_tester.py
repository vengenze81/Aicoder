import unittest
from tester import PenetrationTester, ServiceInfo

class TestPenetrationTester(unittest.TestCase):
    def test_service_info_to_dict(self):
        service = ServiceInfo(port=80, banner="HTTP/1.1")
        d = service.to_dict()
        self.assertEqual(d, {"port": 80, "status": "open", "banner": "HTTP/1.1"})

if __name__ == "__main__":
    unittest.main()

