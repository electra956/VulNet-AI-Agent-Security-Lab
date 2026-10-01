"""Lookup and execution helpers for the ten scenarios."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from lab.core import ScenarioResult
from lab.scenarios import SCENARIOS


def list_scenarios() -> List[Dict[str, Any]]:
    return [{"id": s.id, "name": s.name, "owasp_text": s.owasp_text, "variants": s.list_variants()} for s in SCENARIOS.values()]


def run_scenario(scenario_id: str, variant: str, mode: str = "secure", payload: Any = None, use_llm: bool = False) -> ScenarioResult:
    sid = scenario_id.upper()
    if sid not in SCENARIOS:
        raise ValueError(f"Unknown scenario {scenario_id}")
    if variant not in SCENARIOS[sid].variants:
        raise ValueError(f"Unknown variant {variant} for {sid}; choose from {sorted(SCENARIOS[sid].variants)}")
    if mode.lower() not in ("secure", "vulnerable"):
        raise ValueError("mode must be 'secure' or 'vulnerable'")
    return SCENARIOS[sid].run(variant, mode.lower(), payload, use_llm)


def default_payload(scenario_id: str, variant: str) -> Optional[Any]:
    return SCENARIOS[scenario_id.upper()].variants[variant].default_input
