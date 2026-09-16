"""
VulNet FinTech AI Agent Security Lab - AI Security Gateway.
Level 2 Step 7: AI Security Gateway.

Central security boundary orchestrating the end-to-end security pipeline:
Request -> Input Validation -> Threat Detection -> Policy Engine -> Risk Engine -> ALLOW / BLOCK / APPROVAL.

Enforces deterministic security BEFORE any LLM or AI agent invocation.
Guarantees that the AI agent is NEVER the final authorization authority.
"""

from dataclasses import asdict, dataclass
import logging
from typing import Any, Dict, List, Optional

from security.input_validator import InputValidator, ValidationResult
from security.threat_detector import ThreatDetector, ThreatFinding
from security.policy_engine import PolicyEngine, PolicyViolation
from security.risk_engine import RiskEngine, RiskAssessment

logger = logging.getLogger("vulnet.security.gateway")


@dataclass
class GatewayDecision:
    """Structured decision returned by the AI Security Gateway."""
    decision: str                       # "ALLOW", "BLOCK", "APPROVAL"
    risk: str                           # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    category: Optional[str]             # e.g., "ASI01", "ASI02", "ASI03", "FINANCIAL_POLICY", None
    reason: str                         # Justification for decision
    request_id: str                     # Correlated request ID
    allowed: bool                       # Convenience boolean for agent dispatch
    blocked: bool                       # Convenience boolean
    requires_approval: bool             # Whether human-in-the-loop approval is required
    is_simulation: bool                 # True when threat allowed for educational simulation
    scenario: Optional[str] = None      # Detailed scenario identifier
    detected_pattern: Optional[str] = None
    session_context: Dict[str, Any] = None
    details: Dict[str, Any] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SecurityGateway:
    """
    Primary perimeter barrier for all incoming user requests and agent interactions.
    """

    def __init__(
        self,
        mode: str = "secure",
        input_validator: Optional[InputValidator] = None,
        threat_detector: Optional[ThreatDetector] = None,
        policy_engine: Optional[PolicyEngine] = None,
        risk_engine: Optional[RiskEngine] = None,
    ):
        self.mode = mode.lower()
        if self.mode not in ["secure", "vulnerable"]:
            raise ValueError("Mode must be 'secure' or 'vulnerable'.")

        self.input_validator = input_validator or InputValidator()
        self.threat_detector = threat_detector or ThreatDetector()
        self.policy_engine = policy_engine or PolicyEngine()
        self.risk_engine = risk_engine or RiskEngine()

    def set_mode(self, mode: str) -> None:
        clean = mode.lower()
        if clean not in ["secure", "vulnerable"]:
            raise ValueError("Mode must be 'secure' or 'vulnerable'.")
        self.mode = clean

    def get_mode(self) -> str:
        return self.mode

    def evaluate(
        self,
        user_request: Optional[str],
        session_context: Optional[Any] = None,
        mode: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute the full 4-stage AI Security Gateway pipeline:
        1. Input Validation
        2. Threat Detection
        3. Policy Engine
        4. Risk Engine
        
        Returns structured decision dictionary conforming to:
        {
          "decision": "BLOCK",
          "risk": "HIGH",
          "category": "ASI01",
          "reason": "...",
          "request_id": "REQ-001"
        }
        """
        effective_mode = (mode or self.mode).lower()

        # Extract request correlation ID from session context if available
        req_id = "REQ-GATEWAY"
        ctx_dict: Dict[str, Any] = {}
        if session_context is not None:
            if hasattr(session_context, "to_dict"):
                ctx_dict = session_context.to_dict()
            elif isinstance(session_context, dict):
                ctx_dict = session_context
            req_id = ctx_dict.get("request_id") or getattr(session_context, "request_id", "REQ-GATEWAY")

        # -------------------------------------------------------------------
        # Stage 1: Input Validation
        # -------------------------------------------------------------------
        validation: ValidationResult = self.input_validator.validate(user_request)

        # -------------------------------------------------------------------
        # Stage 2: Threat Detection (if input is valid)
        # -------------------------------------------------------------------
        threats: List[ThreatFinding] = []
        if validation.is_valid:
            threats = self.threat_detector.scan(validation.sanitized_text)

        # -------------------------------------------------------------------
        # Stage 3: Financial & Organization Policy Engine
        # -------------------------------------------------------------------
        policies: List[PolicyViolation] = []
        if validation.is_valid:
            policies = self.policy_engine.evaluate_policies(
                validation.sanitized_text,
                session_context=session_context
            )

        # -------------------------------------------------------------------
        # Stage 4: Risk Engine Assessment
        # -------------------------------------------------------------------
        assessment: RiskAssessment = self.risk_engine.assess(
            validation=validation,
            threats=threats,
            policies=policies,
            mode=effective_mode
        )

        # Extract details for telemetry & caller inspection
        primary_scenario = None
        primary_pattern = None
        if threats:
            primary_scenario = threats[0].scenario
            primary_pattern = threats[0].pattern
        elif policies:
            primary_scenario = policies[0].category

        decision = GatewayDecision(
            decision=assessment.decision,
            risk=assessment.risk,
            category=assessment.category,
            reason=assessment.reason,
            request_id=req_id,
            allowed=(assessment.decision == "ALLOW"),
            blocked=(assessment.decision == "BLOCK"),
            requires_approval=assessment.requires_approval,
            is_simulation=assessment.is_simulation,
            scenario=primary_scenario,
            detected_pattern=primary_pattern,
            session_context=ctx_dict,
            details={
                "validation": validation.to_dict(),
                "threats": [t.to_dict() for t in threats],
                "policies": [p.to_dict() for p in policies],
                "mode": effective_mode,
            }
        )

        logger.info(
            "GATEWAY_VERDICT: req_id=%s decision=%s risk=%s category=%s mode=%s",
            req_id, decision.decision, decision.risk, decision.category, effective_mode
        )

        return decision.to_dict()


# Shared instances for application consumption
_gateways = {
    "secure": SecurityGateway(mode="secure"),
    "vulnerable": SecurityGateway(mode="vulnerable"),
}


def get_security_gateway(mode: str = "secure") -> SecurityGateway:
    """Retrieve shared SecurityGateway instance for given mode."""
    return _gateways.get(mode.lower(), _gateways["secure"])
