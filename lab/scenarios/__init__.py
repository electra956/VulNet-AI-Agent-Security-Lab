"""Executable OWASP Top 10 for Agentic Applications (2026) scenarios."""

from lab.scenarios.asi01 import ASI01
from lab.scenarios.asi02 import ASI02
from lab.scenarios.asi03 import ASI03
from lab.scenarios.asi04 import ASI04
from lab.scenarios.asi05 import ASI05
from lab.scenarios.asi06 import ASI06
from lab.scenarios.asi07 import ASI07
from lab.scenarios.asi08 import ASI08
from lab.scenarios.asi09 import ASI09
from lab.scenarios.asi10 import ASI10

SCENARIOS = {s.id: s for s in (ASI01, ASI02, ASI03, ASI04, ASI05, ASI06, ASI07, ASI08, ASI09, ASI10)}

__all__ = ["SCENARIOS"] + [s.__name__ for s in SCENARIOS.values()]
