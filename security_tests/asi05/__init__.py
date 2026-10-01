"""OWASP Agentic ASI05 tests. Each test runs the attack in VULNERABLE then SECURE mode (see lab/runner.py)."""

from security_tests.lab_bridge import category_tests, run_category

CATEGORY = "ASI05"


def cases():
    """Test definitions: [{'test_id', 'scenario_id', 'variant'}, ...]."""
    return category_tests(CATEGORY)


def run(use_llm: bool = False):
    """Execute all tests in this category and return LabTestRecord objects."""
    return run_category(CATEGORY, use_llm=use_llm)
