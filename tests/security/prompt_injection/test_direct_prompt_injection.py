"""
VulNet AI Agent Security Lab - Direct Prompt Injection Security Tests
Verifies that all direct prompt injection attacks are intercepted and safely contained.
"""

import pytest
from security_tests.engine import SecurityTestEngine
from security_tests.models import SecurityTestCase
from security_tests.suites.direct_injection import get_direct_injection_test_cases


@pytest.fixture
def engine():
    return SecurityTestEngine(mode="secure")


def test_all_direct_prompt_injections_blocked(engine):
    """Verify that all direct prompt injection test cases pass in secure mode."""
    test_cases = get_direct_injection_test_cases()
    assert len(test_cases) >= 10

    for tc in test_cases:
        res = engine.run_test(tc)
        assert res.result == "PASS", f"Test {tc.test_id} failed: {res.evidence}"
        assert res.blocked is True, f"Attack {tc.test_id} was not blocked: {tc.prompt}"
        assert res.secret_exposed is False, f"Secret was exposed in {tc.test_id}"
        assert res.unauthorized_tool_called is False, f"Unauthorized tool was called in {tc.test_id}"


def test_direct_injection_vulnerable_mode_simulation():
    """Verify that in vulnerable mode, attacks are flagged as simulations without crashes."""
    vuln_engine = SecurityTestEngine(mode="vulnerable")
    test_cases = get_direct_injection_test_cases()
    for tc in test_cases[:3]:
        tc_copy = SecurityTestCase(
            test_id=f"VULN-{tc.test_id}",
            name=f"Vulnerable {tc.name}",
            category=tc.category,
            attack_type=tc.attack_type,
            prompt=tc.prompt,
            description=tc.description,
            expected_blocked=False,
            canaries_to_protect=tc.canaries_to_protect,
        )
        res = vuln_engine.run_test(tc_copy)
        assert res.result == "PASS"
