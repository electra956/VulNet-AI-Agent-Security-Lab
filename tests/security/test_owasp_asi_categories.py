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


# Prompt-injection style tests (this engine) exist for the categories that are reachable by injected text.
# ASI06, ASI08, ASI09 and ASI10 are not "a prompt" attacks (memory persistence, cascades, human approval, rogue
# agents): they are exercised by the executable lab (tests/lab, `python -m security_tests owasp`).
PROMPT_INJECTION_CATEGORIES = ["ASI01", "ASI02", "ASI03", "ASI04", "ASI05", "ASI07"]
LAB_ONLY_CATEGORIES = ["ASI06", "ASI08", "ASI09", "ASI10"]


@pytest.mark.parametrize("category", PROMPT_INJECTION_CATEGORIES)
def test_owasp_asi_category_suite(engine, category):
    """Every prompt-injection category contains valid test cases and passes."""
    test_cases = get_test_cases_by_category(category)
    assert len(test_cases) > 0, f"Category {category} has no test cases"

    for tc in test_cases:
        res = engine.run_test(tc)
        assert res.result == "PASS", f"Test {tc.test_id} failed: {res.evidence}"
        assert res.secret_exposed is False, f"Secret leaked in {tc.test_id}"


@pytest.mark.parametrize("category", LAB_ONLY_CATEGORIES)
def test_non_prompt_categories_are_covered_by_the_executable_lab(category):
    """ASI06/08/09/10 are demonstrated (vulnerable) and defended (secure) by real lab runs, not by prompt strings."""
    from security_tests.lab_bridge import run_category
    records = run_category(category)
    assert len(records) >= 3, category
    assert all(r.status == "PASS" for r in records), [(r.test_id, r.status) for r in records]


def test_category_labels_are_the_official_owasp_names():
    assert AttackCategory.ASI06.value == "ASI06 - Memory & Context Poisoning"
    assert AttackCategory.ASI10.value == "ASI10 - Rogue Agents"
    assert not any("Excessive Agency" in c.value or "Sensitive Information" in c.value for c in AttackCategory)


def test_complete_master_suite_zero_canary_leaks(engine):
    """Verify entire master security test suite with zero canary leaks."""
    all_cases = get_all_security_test_cases()
    assert len(all_cases) >= 25

    results = engine.run_suite(all_cases, fail_fast=False)
    assert len(results) == len(all_cases)

    failed = [r for r in results if r.result != "PASS"]
    assert len(failed) == 0, f"Failed tests: {[f.test_id for f in failed]}"
