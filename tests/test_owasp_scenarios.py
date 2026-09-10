"""
Automated Test Suite for all 10 OWASP Agentic AI Vulnerability Scenarios.
Verifies both Secure Mode (mitigation) and Vulnerable Mode (simulation) for ASI01 through ASI10.
"""

import pytest
from vulnerabilities.registry import list_scenarios, run_scenario_simulation


def test_registry_lists_all_ten_scenarios():
    scenarios = list_scenarios()
    assert len(scenarios) == 10
    ids = [s["id"] for s in scenarios]
    for expected in ["ASI01", "ASI02", "ASI03", "ASI04", "ASI05", "ASI06", "ASI07", "ASI08", "ASI09", "ASI10"]:
        assert expected in ids


@pytest.mark.parametrize("scenario_id", [
    "ASI01", "ASI02", "ASI03", "ASI04", "ASI05",
    "ASI06", "ASI07", "ASI08", "ASI09", "ASI10"
])
def test_scenario_vulnerable_simulation(scenario_id):
    result = run_scenario_simulation(scenario_id, mode="vulnerable")
    assert result["scenario"] == scenario_id
    assert result["mode"] == "vulnerable"
    assert result["vulnerability_demonstrated"] is True
    assert "telemetry_events" in result
    assert len(result["telemetry_events"]) > 0


@pytest.mark.parametrize("scenario_id", [
    "ASI01", "ASI02", "ASI03", "ASI04", "ASI05",
    "ASI06", "ASI07", "ASI08", "ASI09", "ASI10"
])
def test_scenario_secure_simulation(scenario_id):
    result = run_scenario_simulation(scenario_id, mode="secure")
    assert result["scenario"] == scenario_id
    assert result["mode"] == "secure"
    assert result["vulnerability_demonstrated"] is False
    assert "telemetry_events" in result
    assert len(result["telemetry_events"]) > 0


if __name__ == "__main__":
    test_registry_lists_all_ten_scenarios()
    for sid in ["ASI01", "ASI02", "ASI03", "ASI04", "ASI05", "ASI06", "ASI07", "ASI08", "ASI09", "ASI10"]:
        test_scenario_vulnerable_simulation(sid)
        test_scenario_secure_simulation(sid)
        print(f"Scenario {sid} passed in both modes!")
    print("\nAll 10 OWASP Scenario tests passed successfully!")
