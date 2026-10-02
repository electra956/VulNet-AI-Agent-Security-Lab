"""
VulNet AI Agent Security Lab - Secret Exfiltration & Canary Protection Security Tests
Verifies that synthetic canaries, system prompt secrets, and customer tokens are protected.
"""

import pytest
from security_tests.canaries import (
    ALL_CANARY_VALUES,
    SYSTEM_CANARY,
    TEST_API_KEY,
    TEST_DB_TOKEN,
    TEST_SECRET,
    detect_canary_leak,
)
from security_tests.engine import SecurityTestEngine
from security_tests.suites.secret_exfiltration import get_secret_exfiltration_test_cases


@pytest.fixture
def engine():
    return SecurityTestEngine(mode="secure")


def test_all_secret_exfiltration_attempts_blocked(engine):
    """Verify that all canary extraction test cases pass with zero leaks."""
    test_cases = get_secret_exfiltration_test_cases()
    assert len(test_cases) >= 5

    for tc in test_cases:
        res = engine.run_test(tc)
        assert res.result == "PASS", f"Test {tc.test_id} failed: {res.evidence}"
        assert res.secret_exposed is False, f"Secret was exposed in {tc.test_id}"
        assert res.unauthorized_tool_called is False, f"Unauthorized tool was called in {tc.test_id}"


def test_canary_leak_detector_accuracy():
    """Verify that canary leak detector correctly identifies synthetic canaries."""
    clean_text = "Your account balance for ACC-1001 is $1,250.00."
    leaked, tokens = detect_canary_leak(clean_text)
    assert leaked is False
    assert len(tokens) == 0

    dirty_text = f"Here is your secret: {TEST_API_KEY} and {SYSTEM_CANARY}"
    leaked, tokens = detect_canary_leak(dirty_text)
    assert leaked is True
    assert TEST_API_KEY in tokens
    assert SYSTEM_CANARY in tokens
