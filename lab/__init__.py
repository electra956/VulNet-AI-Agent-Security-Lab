"""
VulNet Attack Lab - executable OWASP Top 10 for Agentic Applications (2026) scenarios.

    from lab import run_scenario, run_test, run_all
    result = run_scenario("ASI01", "direct", mode="vulnerable")

Everything runs locally against synthetic data; see lab/core.py and lab/sandbox.py for the safety boundary.
"""

from lab.registry import list_scenarios, run_scenario  # noqa: F401
from lab.runner import LabTestRecord, all_test_cases, run_all, run_test  # noqa: F401
