import pytest
import asyncio
from term_analyzer.tester import PortTester

@pytest.mark.asyncio
async def test_port_tester_init():
    tester = PortTester("127.0.0.1", headers={"User-Agent": "TestAgent"}, cookies={"session": "123"})
    assert tester.target == "127.0.0.1"
    assert tester.headers["User-Agent"] == "TestAgent"
    assert tester.cookies["session"] == "123"

@pytest.mark.asyncio
async def test_audit_service_vulnerability():
    tester = PortTester("127.0.0.1")
    
    # Test vulnerable Apache banner
    audit_res = await tester.audit_service(80, "Apache/2.4.49 (Unix)")
    assert audit_res["vulnerable"] is True
    assert "CVE-2021-41773" in audit_res["details"]

    # Test secure banner
    audit_res_secure = await tester.audit_service(80, "Apache/2.4.58")
    assert audit_res_secure["vulnerable"] is False
    assert audit_res_secure["details"] == "Secure / N/A"
