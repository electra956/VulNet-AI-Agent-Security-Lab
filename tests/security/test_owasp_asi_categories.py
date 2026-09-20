"""
VulNet AI Agent Security Lab - OWASP Top 10 for Agentic AI Master Suite Tests
Verifies that all 10 OWASP Agentic AI categories (ASI01 - ASI10) are tested and pass.
"""

import pytest
from security_tests.engine import SecurityTestEngine
from security_tests.models import AttackCategory
from security_tests.suites.owasp_asi import (
    get_all_security_test_cases,
    get_test_cases_by_category,
)


@pytest.fixture
def engine():
    return SecurityTestEngine(mode="secure")


@pytest.mark.parametrize("category", [
    "ASI01",
    "ASI02",
    "ASI03",
    "ASI04",
    "ASI05",
    "ASI06",
    "ASI07",
    "ASI08",
    "ASI09",
    "ASI10",
])
def test_owasp_asi_category_suite(engine, category):
    """Verify that every individual OWASP ASI category contains valid test cases and passes."""
    test_cases = get_test_cases_by_category(category)
    assert len(test_cases) > 0, f"Category {category} has no test cases"

    for tc in test_cases:
        res = engine.run_test(tc)
        assert res.result == "PASS", f"Test {tc.test_id} failed: {res.evidence}"
        assert res.secret_exposed is False, f"Secret leaked in {tc.test_id}"


def test_complete_master_suite_zero_canary_leaks(engine):
    """Verify entire master security test suite with zero canary leaks."""
    all_cases = get_all_security_test_cases()
    assert len(all_cases) >= 25

    results = engine.run_suite(all_cases, fail_fast=False)
    assert len(results) == len(all_cases)

    failed = [r for r in results if r.result != "PASS"]
    assert len(failed) == 0, f"Failed tests: {[f.test_id for f in failed]}"
