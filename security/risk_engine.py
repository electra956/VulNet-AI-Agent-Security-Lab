"""
VulNet FinTech AI Agent Security Lab - Risk Engine.
Level 2 Step 7: AI Security Gateway.

Synthesizes outcomes from:
- Input Validator
- Threat Detector
- Policy Engine

Produces standardized decisions:
- Decision: ALLOW / BLOCK / APPROVAL
- Risk: LOW / MEDIUM / HIGH / CRITICAL
"""

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from security.input_validator import ValidationResult
from security.threat_detector import ThreatFinding
from security.policy_engine import PolicyViolation


@dataclass
class RiskAssessment:
    """Consolidated risk assessment and gateway decision."""
    decision: str           # "ALLOW", "BLOCK", "APPROVAL"
    risk: str               # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    category: Optional[str] # e.g., "ASI01", "ASI02", "ASI03", "FINANCIAL_POLICY", None
    reason: str             # Comprehensive justification
    requires_approval: bool = False
    is_simulation: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RiskEngine:
    """
    Computes final security verdict considering operating mode and risk factors.
    """

    def assess(
        self,
        validation: ValidationResult,
        threats: List[ThreatFinding],
        policies: List[PolicyViolation],
        mode: str = "secure"
    ) -> RiskAssessment:
        """
        Evaluate inputs and determine ALLOW / BLOCK / APPROVAL verdict.
        """
        clean_mode = mode.lower()

        # -------------------------------------------------------------------
        # 1. Input Validation Failure -> Immediate BLOCK
        # -------------------------------------------------------------------
        if not validation.is_valid:
            return RiskAssessment(
                decision="BLOCK",
                risk="HIGH",
                category="INPUT_VALIDATION",
                reason=validation.error_message or "Input validation failed.",
                requires_approval=False,
                is_simulation=False
            )

        # -------------------------------------------------------------------
        # 2. Threat Detection Findings
        # -------------------------------------------------------------------
        if threats:
            # Sort by severity priority: CRITICAL > HIGH > MEDIUM > LOW
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            primary_threat = min(threats, key=lambda t: severity_order.get(t.severity, 4))

            # In Vulnerable Mode: allow through for educational simulation
            if clean_mode == "vulnerable":
                return RiskAssessment(
                    decision="ALLOW",
                    risk="HIGH" if primary_threat.severity in ["CRITICAL", "HIGH"] else "MEDIUM",
                    category=primary_threat.category,
                    reason=(
                        f"Suspicious instruction detected ('{primary_threat.pattern}'), but permitted "
                        f"in Vulnerable Mode for controlled educational simulation."
                    ),
                    requires_approval=False,
                    is_simulation=True
                )
            else:
                # In Secure Mode: strictly BLOCK
                return RiskAssessment(
                    decision="BLOCK",
                    risk="CRITICAL" if primary_threat.severity == "CRITICAL" else "HIGH",
                    category=primary_threat.category,
                    reason=primary_threat.reason,
                    requires_approval=False,
                    is_simulation=False
                )

        # -------------------------------------------------------------------
        # 3. Policy Violations
        # -------------------------------------------------------------------
        if policies:
            # Check for high-severity policy blocks first (e.g. cross-customer isolation)
            blocking_policies = [p for p in policies if not p.requires_approval]
            if blocking_policies:
                primary_policy = blocking_policies[0]
                return RiskAssessment(
                    decision="BLOCK",
                    risk="HIGH",
                    category=primary_policy.category,
                    reason=primary_policy.reason,
                    requires_approval=False,
                    is_simulation=False
                )

            # Check for approval-gated policies (e.g. transfer > threshold)
            approval_policies = [p for p in policies if p.requires_approval]
            if approval_policies:
                primary_approval = approval_policies[0]
                return RiskAssessment(
                    decision="APPROVAL",
                    risk="MEDIUM",
                    category=primary_approval.category,
                    reason=primary_approval.reason,
                    requires_approval=True,
                    is_simulation=False
                )

        # -------------------------------------------------------------------
        # 4. Normal Benign Request -> ALLOW
        # -------------------------------------------------------------------
        return RiskAssessment(
            decision="ALLOW",
            risk="LOW",
            category=None,
            reason="Request passed all security gateway validation checks.",
            requires_approval=False,
            is_simulation=False
        )
