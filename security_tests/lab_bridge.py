"""Bridge between the `security_tests/asiNN/` packages and the executable OWASP lab (`lab/`)."""

from __future__ import annotations

from typing import Dict, List

from lab.runner import LabTestRecord, all_test_cases, run_test


def category_tests(category: str) -> List[Dict[str, str]]:
    """Test definitions (id, scenario, variant) for one OWASP category, e.g. 'ASI03'."""
    return [t for t in all_test_cases() if t["scenario_id"] == category.upper()]


def run_category(category: str, use_llm: bool = False) -> List[LabTestRecord]:
    """Execute every test of a category (each runs the attack in vulnerable and in secure mode)."""
    return [run_test(t["scenario_id"], t["variant"], use_llm=use_llm) for t in category_tests(category)]


def run_one(test_id: str, use_llm: bool = False) -> LabTestRecord:
    for t in all_test_cases():
        if t["test_id"] == test_id.upper():
            return run_test(t["scenario_id"], t["variant"], use_llm=use_llm)
    raise KeyError(test_id)
