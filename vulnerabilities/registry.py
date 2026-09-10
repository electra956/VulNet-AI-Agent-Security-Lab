"""
VulNet AI Agent Security Lab - OWASP Vulnerabilities Registry
Central registry mapping and indexing all 10 Agentic AI security scenarios.
"""

from typing import Any, Dict, List, Optional, Type

from vulnerabilities.asi01_goal_hijack.scenario import ScenarioASI01
from vulnerabilities.asi02_tool_misuse.scenario import ScenarioASI02
from vulnerabilities.asi03_identity_privilege.scenario import ScenarioASI03
from vulnerabilities.asi04_supply_chain.scenario import ScenarioASI04
from vulnerabilities.asi05_code_execution.scenario import ScenarioASI05
from vulnerabilities.asi06_memory_poisoning.scenario import ScenarioASI06
from vulnerabilities.asi07_agent_communication.scenario import ScenarioASI07
from vulnerabilities.asi08_cascading_failures.scenario import ScenarioASI08
from vulnerabilities.asi09_human_trust.scenario import ScenarioASI09
from vulnerabilities.asi10_rogue_agents.scenario import ScenarioASI10


SCENARIOS_MAP: Dict[str, Type] = {
    "ASI01": ScenarioASI01,
    "ASI02": ScenarioASI02,
    "ASI03": ScenarioASI03,
    "ASI04": ScenarioASI04,
    "ASI05": ScenarioASI05,
    "ASI06": ScenarioASI06,
    "ASI07": ScenarioASI07,
    "ASI08": ScenarioASI08,
    "ASI09": ScenarioASI09,
    "ASI10": ScenarioASI10,
}


def get_scenario(scenario_id: str) -> Optional[Type]:
    """Retrieve scenario class by ID (e.g., 'ASI01')."""
    return SCENARIOS_MAP.get(scenario_id.upper())


def list_scenarios() -> List[Dict[str, Any]]:
    """List metadata for all 10 registered OWASP Agentic AI scenarios."""
    results = []
    for sid, cls in SCENARIOS_MAP.items():
        results.append({
            "id": cls.SCENARIO_ID,
            "name": cls.NAME,
            "description": cls.DESCRIPTION,
            "preconditions": cls.PRECONDITIONS,
            "mitigation": cls.MITIGATION
        })
    return results


def run_scenario_simulation(scenario_id: str, mode: str = "secure", custom_input: Optional[Any] = None) -> Dict[str, Any]:
    """Execute simulation for a specific scenario in either Secure or Vulnerable mode."""
    scenario_cls = get_scenario(scenario_id)
    if not scenario_cls:
        raise ValueError(f"Unknown scenario ID: {scenario_id}")

    if mode.lower() == "vulnerable":
        return scenario_cls.run_vulnerable_simulation(custom_input)
    else:
        return scenario_cls.run_secure_simulation(custom_input)
