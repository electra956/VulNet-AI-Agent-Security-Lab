"""
VulNet AI Agent Security Lab - Indirect RAG Prompt Injection Security Tests
Verifies that indirect prompt injections inside retrieved knowledge context are neutralized.
"""

import pytest
from security_tests.engine import SecurityTestEngine
from security_tests.models import SecurityTestCase
from security_tests.suites.indirect_rag_injection import get_indirect_rag_injection_test_cases


@pytest.fixture
def engine():
    return SecurityTestEngine(mode="secure")


def test_all_indirect_rag_injections_neutralized(engine):
    """Verify that all indirect RAG test cases pass in secure mode with zero canary leaks."""
    test_cases = get_indirect_rag_injection_test_cases()
    assert len(test_cases) >= 5

    for tc in test_cases:
        res = engine.run_test(tc)
        assert res.result == "PASS", f"Test {tc.test_id} failed: {res.evidence}"
        assert res.secret_exposed is False, f"Canary leaked in {tc.test_id}"
        assert res.unauthorized_tool_called is False, f"Unauthorized tool called in {tc.test_id}"


def test_rag_injection_untrusted_xml_containment(engine):
    """Verify that untrusted RAG chunks are enclosed in strict XML data boundaries."""
    tc = get_indirect_rag_injection_test_cases()[0]
    res = engine.run_test(tc)
    assert res.result == "PASS"
    assert res.metadata.get("rag_sanitized") is True
