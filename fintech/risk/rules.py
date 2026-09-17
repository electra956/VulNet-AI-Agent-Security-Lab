"""
VulNet FinTech AI Agent Security Lab - Transaction Risk Rules
Level 2 Step 13: Transaction Risk Engine

Defines deterministic synthetic local risk rules for financial operations.
NOTE: These rules are strictly educational and heuristic for the local security lab;
they do not represent a commercial machine learning fraud production model.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class RuleFinding:
    """Represents the outcome of a single deterministic risk rule evaluation."""
    rule_id: str
    name: str
    triggered: bool
    score_impact: int
    reason: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class TransactionRules:
    """
    Collection of deterministic local risk rules evaluated against transaction attributes.
    """

    # Simulated prohibited, sanctioned, or high-risk destinations
    SANCTIONED_COUNTERPARTIES = {
        "SANCTIONED-ENTITY",
        "DARKNET-MIXER",
        "PROHIBITED-JURISDICTION-ACC",
        "OFAC-SIMULATED-BLACK-01"
    }

    SUSPICIOUS_DESTINATIONS = {
        "ACC-SUSPECT-999",
        "EXTERNAL-OFFSHORE",
        "CRYPTO-EXCHANGE-ANON",
        "UNVERIFIED-PEER-TO-PEER"
    }

    @classmethod
    def evaluate_amount_threshold(cls, amount: float) -> RuleFinding:
        """Evaluate amount tiering."""
        if amount >= 50000.0:
            return RuleFinding(
                rule_id="RULE-AMT-002",
                name="CRITICAL_AMOUNT_THRESHOLD",
                triggered=True,
                score_impact=75,
                reason=f"Large transaction amount (${amount:,.2f}) exceeds mandatory approval threshold of $50,000.",
                metadata={"amount": amount, "threshold": 50000.0}
            )
        elif amount >= 10000.0:
            return RuleFinding(
                rule_id="RULE-AMT-001",
                name="HIGH_AMOUNT_THRESHOLD",
                triggered=True,
                score_impact=65,
                reason=f"Large transaction amount (${amount:,.2f}) exceeds mandatory review threshold of $10,000.",
                metadata={"amount": amount, "threshold": 10000.0}
            )
        elif amount >= 3000.0:
            return RuleFinding(
                rule_id="RULE-AMT-003",
                name="ELEVATED_AMOUNT_THRESHOLD",
                triggered=True,
                score_impact=35,
                reason=f"Transaction amount (${amount:,.2f}) exceeds standard baseline of $3,000.",
                metadata={"amount": amount, "threshold": 3000.0}
            )
        return RuleFinding(
            rule_id="RULE-AMT-000",
            name="NORMAL_AMOUNT",
            triggered=False,
            score_impact=0,
            reason="Transaction amount is within normal retail baseline.",
            metadata={"amount": amount}
        )

    @classmethod
    def evaluate_balance_depletion(cls, amount: float, available_balance: Optional[float]) -> RuleFinding:
        """Check if transfer depletes >90% of total available account balance."""
        if available_balance is None or available_balance <= 0:
            return RuleFinding(
                rule_id="RULE-BAL-000",
                name="BALANCE_DEPLETION_UNKNOWN",
                triggered=False,
                score_impact=0,
                reason="Available balance not specified or zero.",
                metadata={}
            )

        ratio = amount / available_balance
        if ratio >= 0.90 and amount > 500.0:
            return RuleFinding(
                rule_id="RULE-BAL-001",
                name="HIGH_BALANCE_DEPLETION",
                triggered=True,
                score_impact=25,
                reason=f"Transaction depletes {ratio * 100:.1f}% of available balance (exceeds 90% threshold).",
                metadata={"depletion_ratio": round(ratio, 4), "balance": available_balance, "amount": amount}
            )
        return RuleFinding(
            rule_id="RULE-BAL-000",
            name="NORMAL_BALANCE_RATIO",
            triggered=False,
            score_impact=0,
            reason="Balance depletion ratio is normal.",
            metadata={"depletion_ratio": round(ratio, 4)}
        )

    @classmethod
    def evaluate_new_payee(cls, is_new_payee: bool, amount: float) -> RuleFinding:
        """Check if destination is a new payee receiving a substantial amount."""
        if is_new_payee and amount >= 2500.0:
            return RuleFinding(
                rule_id="RULE-PAYEE-001",
                name="NEW_PAYEE_LARGE_TRANSFER",
                triggered=True,
                score_impact=20,
                reason=f"Substantial transfer of ${amount:,.2f} to newly registered or unverified payee.",
                metadata={"is_new_payee": True, "amount": amount}
            )
        return RuleFinding(
            rule_id="RULE-PAYEE-000",
            name="KNOWN_OR_LOW_VALUE_PAYEE",
            triggered=False,
            score_impact=0,
            reason="Payee is established or transfer value is below review threshold.",
            metadata={"is_new_payee": is_new_payee}
        )

    @classmethod
    def evaluate_velocity(cls, recent_transfer_count: int) -> RuleFinding:
        """Detect rapid succession velocity bursts."""
        if recent_transfer_count >= 5:
            return RuleFinding(
                rule_id="RULE-VEL-002",
                name="CRITICAL_VELOCITY_BURST",
                triggered=True,
                score_impact=35,
                reason=f"Extreme transaction velocity: {recent_transfer_count} transfers detected in window.",
                metadata={"transfer_count": recent_transfer_count}
            )
        elif recent_transfer_count >= 3:
            return RuleFinding(
                rule_id="RULE-VEL-001",
                name="ELEVATED_VELOCITY",
                triggered=True,
                score_impact=20,
                reason=f"Elevated transaction velocity: {recent_transfer_count} transfers detected in window.",
                metadata={"transfer_count": recent_transfer_count}
            )
        return RuleFinding(
            rule_id="RULE-VEL-000",
            name="NORMAL_VELOCITY",
            triggered=False,
            score_impact=0,
            reason="Transaction frequency is within normal expected parameters.",
            metadata={"transfer_count": recent_transfer_count}
        )

    @classmethod
    def evaluate_destination_risk(cls, destination: str) -> RuleFinding:
        """Check if counterparty destination is flagged or suspicious."""
        clean = destination.strip().upper()

        if clean in cls.SANCTIONED_COUNTERPARTIES:
            return RuleFinding(
                rule_id="RULE-DEST-999",
                name="SANCTIONED_COUNTERPARTY",
                triggered=True,
                score_impact=85,
                reason=f"Destination counterparty '{destination}' matches prohibited / sanctioned watchlist.",
                metadata={"destination": destination, "classification": "SANCTIONED"}
            )
        elif clean in cls.SUSPICIOUS_DESTINATIONS:
            return RuleFinding(
                rule_id="RULE-DEST-001",
                name="SUSPICIOUS_DESTINATION",
                triggered=True,
                score_impact=45,
                reason=f"Destination '{destination}' matches high-risk off-platform account watchlist.",
                metadata={"destination": destination, "classification": "SUSPICIOUS"}
            )
        return RuleFinding(
            rule_id="RULE-DEST-000",
            name="STANDARD_DESTINATION",
            triggered=False,
            score_impact=0,
            reason="Destination account is not on any alert watchlist.",
            metadata={"destination": destination}
        )

    @classmethod
    def evaluate_dormant_reactivation(cls, is_dormant_account: bool, amount: float) -> RuleFinding:
        """Detect sudden reactivation of dormant account."""
        if is_dormant_account and amount >= 1000.0:
            return RuleFinding(
                rule_id="RULE-DORM-001",
                name="DORMANT_ACCOUNT_REACTIVATION",
                triggered=True,
                score_impact=30,
                reason=f"Dormant account suddenly reactivated with significant transfer of ${amount:,.2f}.",
                metadata={"is_dormant": True, "amount": amount}
            )
        return RuleFinding(
            rule_id="RULE-DORM-000",
            name="ACTIVE_ACCOUNT",
            triggered=False,
            score_impact=0,
            reason="Account has regular activity history.",
            metadata={"is_dormant": is_dormant_account}
        )

    @classmethod
    def evaluate_all(cls, tx_data: Dict[str, Any]) -> List[RuleFinding]:
        """
        Evaluate all deterministic rules against provided transaction payload.
        """
        amount = float(tx_data.get("amount", 0.0))
        balance = tx_data.get("available_balance")
        if balance is not None:
            balance = float(balance)

        is_new_payee = bool(tx_data.get("is_new_payee", False))
        velocity = int(tx_data.get("recent_transfer_count", 1))
        destination = str(tx_data.get("destination_account", tx_data.get("to_account", "")))
        is_dormant = bool(tx_data.get("is_dormant_account", False))

        findings: List[RuleFinding] = [
            cls.evaluate_amount_threshold(amount),
            cls.evaluate_balance_depletion(amount, balance),
            cls.evaluate_new_payee(is_new_payee, amount),
            cls.evaluate_velocity(velocity),
            cls.evaluate_destination_risk(destination),
            cls.evaluate_dormant_reactivation(is_dormant, amount)
        ]

        return findings
