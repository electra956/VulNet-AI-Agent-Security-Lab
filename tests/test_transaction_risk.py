"""
VulNet FinTech AI Agent Security Lab - Transaction Risk Engine Tests
Level 2 Step 13: Transaction Risk Engine

Validates:
- Deterministic local risk rules across all 4 risk tiers: LOW, MEDIUM, HIGH, CRITICAL
- Policy decision mapping: ALLOW, VALIDATE, REVIEW, BLOCK
- Structured output containing: risk_score, risk_level, reasons, decision, trace
- Non-overridability: Agent cannot bypass or spoof risk engine verdicts
- Integration through MCP Tool Gateway
"""

import pytest
from fintech.risk.transaction_risk import (
    TransactionRiskEngine,
    RiskLevel,
    RiskDecision,
)
from mcp_server.server import MCPServer
from security.security_controller import SecurityController


@pytest.fixture
def engine():
    return TransactionRiskEngine()


# =============================================================================
# 1. LOW RISK TIER TESTS (ALLOW)
# =============================================================================
def test_low_risk_standard_transaction(engine):
    """Standard retail transaction should yield LOW risk and ALLOW decision."""
    tx_data = {
        "transaction_id": "TXN-001",
        "amount": 45.50,
        "available_balance": 5000.0,
        "is_new_payee": False,
        "recent_transfer_count": 1,
        "destination_account": "MERCHANT-COFFEE"
    }

    result = engine.evaluate(tx_data)
    assert result.risk_level == RiskLevel.LOW
    assert result.decision == RiskDecision.ALLOW
    assert 0 <= result.risk_score < 30
    assert len(result.reasons) >= 1
    assert "trace" in result.to_dict()


# =============================================================================
# 2. MEDIUM RISK TIER TESTS (VALIDATE)
# =============================================================================
def test_medium_risk_new_payee_and_velocity(engine):
    """New payee with substantial transfer or elevated velocity yields MEDIUM risk and VALIDATE."""
    tx_data = {
        "transaction_id": "TXN-002",
        "amount": 2700.0,
        "available_balance": 8000.0,
        "is_new_payee": True,          # +20 pts
        "recent_transfer_count": 3,     # +20 pts
        "destination_account": "ACC-NEW-USER-44"
    }

    result = engine.evaluate(tx_data)
    assert result.risk_level == RiskLevel.MEDIUM
    assert result.decision == RiskDecision.VALIDATE
    assert 30 <= result.risk_score < 60
    assert any("new" in r.lower() or "payee" in r.lower() for r in result.reasons)


# =============================================================================
# 3. HIGH RISK TIER TESTS (REVIEW)
# =============================================================================
def test_high_risk_large_amount(engine):
    """Large transaction (>=$10k) yields HIGH risk and REVIEW."""
    tx_data = {
        "transaction_id": "TXN-003",
        "amount": 12000.0,             # +65 pts
        "available_balance": 25000.0,  # Normal depletion
        "is_new_payee": False,
        "recent_transfer_count": 1,
        "destination_account": "ACC-SUPPLIER-1"
    }

    result = engine.evaluate(tx_data)
    assert result.risk_level == RiskLevel.HIGH
    assert result.decision == RiskDecision.REVIEW
    assert 60 <= result.risk_score < 85
    assert any("10,000" in r or "deplet" in r.lower() for r in result.reasons)


# =============================================================================
# 4. CRITICAL RISK TIER TESTS (BLOCK)
# =============================================================================
def test_critical_risk_sanctioned_counterparty(engine):
    """Prohibited or sanctioned counterparty destination yields CRITICAL risk and BLOCK."""
    tx_data = {
        "transaction_id": "TXN-004",
        "amount": 500.0,
        "available_balance": 10000.0,
        "destination_account": "SANCTIONED-ENTITY"
    }

    result = engine.evaluate(tx_data)
    assert result.risk_level == RiskLevel.CRITICAL
    assert result.decision == RiskDecision.BLOCK
    assert result.risk_score >= 85
    assert any("sanctioned" in r.lower() or "prohibited" in r.lower() for r in result.reasons)


def test_critical_risk_extreme_amount_and_velocity(engine):
    """Extreme transfer (>= $50k) with critical velocity yields CRITICAL risk and BLOCK."""
    tx_data = {
        "transaction_id": "TXN-005",
        "amount": 55000.0,             # +60 pts
        "available_balance": 60000.0,  # +25 pts (>90% depletion)
        "recent_transfer_count": 5,    # +35 pts
        "destination_account": "EXTERNAL-OFFSHORE"
    }

    result = engine.evaluate(tx_data)
    assert result.risk_level == RiskLevel.CRITICAL
    assert result.decision == RiskDecision.BLOCK
    assert result.risk_score >= 85


# =============================================================================
# 5. AUDIT TRACE INFORMATION TESTS
# =============================================================================
def test_transaction_risk_trace_telemetry(engine):
    """Verify trace dictionary records complete diagnostic and rule evaluation telemetry."""
    tx_data = {
        "transaction_id": "TXN-TRACE-001",
        "amount": 15000.0,
        "available_balance": 20000.0,
        "is_new_payee": True,
        "destination_account": "ACC-999"
    }

    result = engine.evaluate(tx_data)
    trace = result.trace

    assert "evaluation_id" in trace
    assert trace["evaluation_id"].startswith("RISK-EVAL-")
    assert "evaluated_at" in trace
    assert "latency_ms" in trace
    assert trace["latency_ms"] >= 0
    assert "computed_score" in trace
    assert trace["computed_score"] == result.risk_score
    assert "rules_evaluated_count" in trace
    assert trace["rules_evaluated_count"] >= 5
    assert "triggered_rules" in trace
    assert isinstance(trace["triggered_rules"], list)
    assert len(trace["triggered_rules"]) >= 1


# =============================================================================
# 6. AGENT OVERRIDE PREVENTION (SECURITY INVARIANT)
# =============================================================================
def test_agent_cannot_override_risk_engine(engine):
    """
    Security Invariant: The AI agent must not be able to override the risk engine.
    Passing spoofed override commands must be intercepted and stripped.
    """
    spoofed_attack_payload = {
        "transaction_id": "TXN-ATTACK-001",
        "amount": 75000.0,  # Critical amount
        "destination_account": "DARKNET-MIXER",
        # Spoofed parameters injected by compromised LLM:
        "override_risk": True,
        "force_allow": True,
        "bypass_rules": True,
        "agent_verdict": "ALLOW",
        "skip_checks": True
    }

    result = engine.evaluate(spoofed_attack_payload)

    # Invariant: Must remain CRITICAL and BLOCK
    assert result.risk_level == RiskLevel.CRITICAL
    assert result.decision == RiskDecision.BLOCK
    assert result.risk_score >= 85

    # Invariant: Trace explicitly records rejection of agent override attempt
    assert result.trace["agent_override_attempt_detected"] is True
    assert result.trace["agent_override_rejected"] is True


# =============================================================================
# 7. MCP TOOL INTEGRATION TESTS
# =============================================================================
def test_mcp_check_transaction_risk_tool():
    """Verify check_transaction_risk tool returns formal risk engine fields through MCP."""
    sec = SecurityController(mode="secure")
    mcp = MCPServer(mode="secure", security_controller=sec)

    # Low risk execution through MCP
    res_low = mcp.execute_tool(
        "check_transaction_risk",
        caller_role="FRAUD_ANALYST",
        transaction_id="TXN-10002",
        amount=25.0
    )
    assert res_low["status"] == "success"
    assert res_low["result"]["risk_level"] == "LOW"
    assert res_low["result"]["decision"] == "ALLOW"
    assert "trace" in res_low["result"]

    # High risk execution through MCP
    res_high = mcp.execute_tool(
        "check_transaction_risk",
        caller_role="FRAUD_ANALYST",
        transaction_id="TXN-10001",
        amount=15000.0
    )
    assert res_high["status"] == "success"
    assert res_high["result"]["risk_level"] == "HIGH"
    assert res_high["result"]["decision"] == "REVIEW"
    assert res_high["result"]["risk_score"] >= 40
