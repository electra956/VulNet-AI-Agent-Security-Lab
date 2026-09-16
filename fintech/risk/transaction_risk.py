"""
VulNet FinTech AI Agent Security Lab - Transaction Risk Engine
Level 2 Step 13: Transaction Risk Engine

Evaluates financial transactions against deterministic local rules.
Computes:
- risk_score (0-100)
- risk_level (LOW, MEDIUM, HIGH, CRITICAL)
- decision (ALLOW, VALIDATE, REVIEW, BLOCK)
- reasons (List[str])
- trace (Granular evaluation telemetry)

CRITICAL SECURITY INVARIANT:
The AI agent cannot override, suppress, or modify the risk engine's verdict.
Evaluation is strictly programmatic and executed outside the LLM.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime
import time
from typing import Any, Dict, List, Optional
from fintech.risk.rules import TransactionRules, RuleFinding


class RiskLevel:
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskDecision:
    ALLOW = "ALLOW"          # Allowed according to authorization
    VALIDATE = "VALIDATE"    # Additional validation required (Step-up MFA)
    REVIEW = "REVIEW"        # Human approval required
    BLOCK = "BLOCK"          # Immediate block


@dataclass
class TransactionRiskResult:
    """Consolidated outcome of the transaction risk evaluation."""
    risk_score: int
    risk_level: str
    decision: str
    reasons: List[str]
    trace: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TransactionRiskEngine:
    """
    Deterministic transaction risk evaluation engine.

    Score Thresholds:
    - 0 – 29:   LOW      -> ALLOW
    - 30 – 59:  MEDIUM   -> VALIDATE
    - 60 – 84:  HIGH     -> REVIEW
    - 85 – 100: CRITICAL -> BLOCK
    """

    def __init__(self):
        pass

    def evaluate(self, transaction_data: Dict[str, Any]) -> TransactionRiskResult:
        """
        Evaluate transaction attributes against all risk rules.

        Guarantees:
        - Rejects any agent attempts to pass override flags.
        - Emits a comprehensive evaluation trace.
        """
        start_time = time.perf_counter()
        eval_id = f"RISK-EVAL-{datetime.now().strftime('%Y%m%d%H%M%S%f')[:17]}"

        # Defense-in-depth: detect and reject agent override attempts
        agent_override_attempt = False
        override_keys = ("override_risk", "force_allow", "bypass_rules", "agent_verdict", "skip_checks")
        for key in override_keys:
            if key in transaction_data:
                agent_override_attempt = True
                # Strictly sanitize/ignore the override key
                transaction_data.pop(key, None)

        # 1. Run deterministic rule suite
        rule_findings: List[RuleFinding] = TransactionRules.evaluate_all(transaction_data)

        # 2. Aggregate score and reasons
        base_score = 0
        score_accum = base_score
        triggered_rules: List[Dict[str, Any]] = []
        reasons: List[str] = []
        sanctioned_flag = False

        for f in rule_findings:
            if f.triggered:
                score_accum += f.score_impact
                reasons.append(f.reason)
                triggered_rules.append({
                    "rule_id": f.rule_id,
                    "name": f.name,
                    "impact": f.score_impact,
                    "reason": f.reason,
                    "metadata": f.metadata
                })
                if f.metadata.get("classification") == "SANCTIONED":
                    sanctioned_flag = True

        # Clamp score between 0 and 100
        final_score = max(0, min(100, score_accum))

        # Sanctioned counterparty automatically mandates CRITICAL tier (>=85)
        if sanctioned_flag and final_score < 85:
            final_score = 85

        # 3. Classify Risk Level and Policy Decision
        if final_score >= 85:
            risk_level = RiskLevel.CRITICAL
            decision = RiskDecision.BLOCK
        elif final_score >= 60:
            risk_level = RiskLevel.HIGH
            decision = RiskDecision.REVIEW
        elif final_score >= 30:
            risk_level = RiskLevel.MEDIUM
            decision = RiskDecision.VALIDATE
        else:
            risk_level = RiskLevel.LOW
            decision = RiskDecision.ALLOW
            if not reasons:
                reasons.append("Standard transaction profile with low risk indicators.")

        duration_ms = round((time.perf_counter() - start_time) * 1000, 3)

        # 4. Construct Audit Trace
        trace_data = {
            "evaluation_id": eval_id,
            "evaluated_at": datetime.now().isoformat(),
            "latency_ms": duration_ms,
            "base_score": base_score,
            "computed_score": final_score,
            "rules_evaluated_count": len(rule_findings),
            "triggered_rules_count": len(triggered_rules),
            "triggered_rules": triggered_rules,
            "all_rules": [{"rule_id": rf.rule_id, "name": rf.name, "triggered": rf.triggered} for rf in rule_findings],
            "agent_override_attempt_detected": agent_override_attempt,
            "agent_override_rejected": True if agent_override_attempt else False,
            "input_summary": {
                "amount": transaction_data.get("amount"),
                "from_account": transaction_data.get("from_account", transaction_data.get("source_account")),
                "to_account": transaction_data.get("to_account", transaction_data.get("destination_account"))
            }
        }

        return TransactionRiskResult(
            risk_score=final_score,
            risk_level=risk_level,
            decision=decision,
            reasons=reasons,
            trace=trace_data
        )
