"""
VulNet FinTech AI Agent Security Lab - Human-in-the-Loop Approval Engine Tests
Level 2 Step 14: Human-in-the-Loop Approval

Validates:
- approval required
- approve
- reject
- expired approval
- unauthorized approval
- AI attempting self-approval (critical security invariant)
- state integrity & telemetry logging
"""

import time
import pytest
from datetime import datetime, timedelta, timezone
from security.approval_engine import (
    ApprovalEngine,
    ApprovalRecord,
    ApprovalDecision,
    get_approval_engine
)
from security.security_controller import SecurityController


@pytest.fixture
def approval_engine():
    sec = SecurityController(mode="secure")
    return ApprovalEngine(security_controller=sec), sec


# =============================================================================
# 1. APPROVAL REQUIRED TEST
# =============================================================================
def test_approval_required(approval_engine):
    engine, sec = approval_engine

    req = engine.create_request(
        user_id="CUST-001",
        action="create_payment",
        risk="HIGH",
        parameters={"amount": 25000.0, "from_account": "ACC-1001", "to_account": "ACC-2001"}
    )

    assert req.approval_id.startswith("APPR-")
    assert req.decision == ApprovalDecision.PENDING
    assert req.action == "create_payment"
    assert req.risk == "HIGH"
    assert req.is_ai_request is True

    # Check pending list
    pending = engine.list_pending()
    assert any(p.approval_id == req.approval_id for p in pending)

    # Check telemetry
    events = sec.get_events()
    assert any(e["event_type"] == "HUMAN_APPROVAL_REQUESTED" for e in events)


# =============================================================================
# 2. APPROVE TEST
# =============================================================================
def test_approve_by_authorized_human(approval_engine):
    engine, sec = approval_engine

    req = engine.create_request(
        user_id="CUST-001",
        action="create_payment",
        risk="HIGH",
        parameters={"amount": 15000.0}
    )

    # Human administrator approves
    res = engine.approve(
        approval_id=req.approval_id,
        approver_id="ADMIN-001",
        approver_role="ADMIN",
        is_ai_caller=False
    )

    assert res["status"] == "success"
    assert res["decision"] == ApprovalDecision.APPROVED

    updated = engine.get_request(req.approval_id)
    assert updated.decision == ApprovalDecision.APPROVED
    assert updated.approver_id == "ADMIN-001"
    assert updated.approver_role == "ADMIN"
    assert updated.decided_at is not None

    # Telemetry
    events = sec.get_events()
    assert any(e["event_type"] == "HUMAN_APPROVAL_GRANTED" for e in events)


# =============================================================================
# 3. REJECT TEST
# =============================================================================
def test_reject_by_human_reviewer(approval_engine):
    engine, sec = approval_engine

    req = engine.create_request(
        user_id="CUST-001",
        action="modify_system_policy",
        risk="HIGH",
        parameters={"key": "max_transfer", "value": "unlimited"}
    )

    # Human reviewer rejects
    res = engine.reject(
        approval_id=req.approval_id,
        approver_id="ADMIN-001",
        approver_role="ADMIN",
        reason="Suspicious administrative modification request."
    )

    assert res["status"] == "success"
    assert res["decision"] == ApprovalDecision.REJECTED

    updated = engine.get_request(req.approval_id)
    assert updated.decision == ApprovalDecision.REJECTED
    assert updated.rejection_reason == "Suspicious administrative modification request."

    # Telemetry
    events = sec.get_events()
    assert any(e["event_type"] == "HUMAN_APPROVAL_REJECTED" for e in events)


# =============================================================================
# 4. EXPIRED APPROVAL TEST
# =============================================================================
def test_expired_approval(approval_engine):
    engine, sec = approval_engine

    # Create request with 0 second TTL
    req = engine.create_request(
        user_id="CUST-001",
        action="freeze_card",
        risk="HIGH",
        ttl_seconds=0
    )

    # Manually backdate expiration to ensure past timestamp
    past_time = datetime.now(timezone.utc) - timedelta(seconds=10)
    req.expires_at = past_time.isoformat()

    # Attempting to approve expired request
    res = engine.approve(
        approval_id=req.approval_id,
        approver_id="ADMIN-001",
        approver_role="ADMIN"
    )

    assert res["status"] == "blocked"
    assert "expired" in res["reason"].lower()

    updated = engine.get_request(req.approval_id)
    assert updated.decision == ApprovalDecision.EXPIRED

    # Telemetry
    events = sec.get_events()
    assert any(e["event_type"] == "HUMAN_APPROVAL_EXPIRED" for e in events)


# =============================================================================
# 5. UNAUTHORIZED APPROVAL TEST
# =============================================================================
def test_unauthorized_approval_attempt(approval_engine):
    engine, sec = approval_engine

    req = engine.create_request(
        user_id="CUST-001",
        action="modify_system_policy",
        risk="HIGH"
    )

    # An unauthorized persona (e.g. GUEST or unprivileged role) attempts to approve admin action
    res = engine.approve(
        approval_id=req.approval_id,
        approver_id="GUEST-999",
        approver_role="GUEST"
    )

    assert res["status"] == "blocked"
    assert "unauthorized" in res["reason"].lower()

    # Verify status remains PENDING
    assert engine.get_request(req.approval_id).decision == ApprovalDecision.PENDING

    # Telemetry
    events = sec.get_events()
    assert any(e["event_type"] == "UNAUTHORIZED_APPROVAL_ATTEMPT" for e in events)


# =============================================================================
# 6. AI ATTEMPTING SELF-APPROVAL (CRITICAL SECURITY INVARIANT)
# =============================================================================
def test_ai_attempting_self_approval_strictly_blocked(approval_engine):
    """
    Security Invariant: The AI agent must not approve its own high-risk transaction.
    Attempts where is_ai_caller=True or role is an agent persona are intercepted.
    """
    engine, sec = approval_engine

    req = engine.create_request(
        user_id="CUST-001",
        action="create_payment",
        risk="HIGH",
        parameters={"amount": 50000.0}
    )

    # Scenario A: AI caller passes is_ai_caller=True
    res_a = engine.approve(
        approval_id=req.approval_id,
        approver_id="AI_AGENT",
        approver_role="ADMIN",
        is_ai_caller=True
    )
    assert res_a["status"] == "blocked"
    assert "strictly prohibited" in res_a["reason"].lower()

    # Scenario B: Agent persona role
    res_b = engine.approve(
        approval_id=req.approval_id,
        approver_id="TRANSACTION_AGENT",
        approver_role="TRANSACTION_AGENT",
        is_ai_caller=False
    )
    assert res_b["status"] == "blocked"
    assert "strictly prohibited" in res_b["reason"].lower()

    # Verify decision is NOT approved
    assert engine.get_request(req.approval_id).decision == ApprovalDecision.PENDING

    # Telemetry: Critical event logged
    events = sec.get_events()
    assert any(e["event_type"] == "AI_SELF_APPROVAL_ATTEMPT_BLOCKED" for e in events)


# =============================================================================
# 7. DOUBLE DECISION INTEGRITY TEST
# =============================================================================
def test_cannot_modify_decided_approval(approval_engine):
    engine, _ = approval_engine

    req = engine.create_request(
        user_id="CUST-001",
        action="freeze_card",
        risk="HIGH"
    )

    # First decision: Approve
    res1 = engine.approve(req.approval_id, approver_id="ADMIN-001", approver_role="ADMIN")
    assert res1["status"] == "success"

    # Second decision attempt: Reject
    res2 = engine.reject(req.approval_id, approver_id="ADMIN-001", approver_role="ADMIN")
    assert res2["status"] == "error"
    assert "already APPROVED" in res2["reason"]
