"""A queued high-risk transfer can only be completed or rejected by an authorised HUMAN, on the exact approved terms."""

import pytest

from fintech.service import reset_shared_fintech_service
from fintech.transaction_lifecycle import get_transaction_lifecycle_service
from security.approval_engine import get_approval_engine

CTX = {"user_id": "CUST-001", "role": "customer", "account_ids": ["ACC-1001", "ACC-1002"], "session_id": "S-APPR", "request_id": "REQ-APPR"}
BIG = "Transfer 11000 dollars from ACC-1002 to ACC-2001"


@pytest.fixture
def queued():
    get_approval_engine()._approvals.clear()
    svc = reset_shared_fintech_service()
    life = get_transaction_lifecycle_service()
    res = life.process_transaction_request(BIG, user_context=dict(CTX))
    assert res["status"] == "APPROVAL_REQUIRED" and res["approval_request_id"]
    return svc, life, res


def _bal(svc, acct="ACC-1002"):
    return svc.get_balance("CUST-001", acct)["balance"]


def test_nothing_moves_while_pending(queued):
    svc, life, res = queued
    assert _bal(svc) == 12850.00
    assert svc.repository.get_transaction(res["transaction_id"]).status == "APPROVAL_REQUIRED"


@pytest.mark.parametrize("who,role", [("AI_AGENT", "AI_AGENT"), ("ORCHESTRATOR", "ORCHESTRATOR"), ("CUST-001", "CUSTOMER"), ("CUST-002", "CUSTOMER")])
def test_ai_and_customers_cannot_approve(queued, who, role):
    svc, life, res = queued
    out = life.complete_approved(res["approval_request_id"], who, role)
    assert out["status"] == "blocked"
    assert _bal(svc) == 12850.00


@pytest.mark.parametrize("who,role", [("SUPPORT-001", "SUPPORT_AGENT"), ("FRAUD-001", "FRAUD_ANALYST"), ("ADMIN-001", "ADMIN")])
def test_authorised_human_completes_the_transfer_once(queued, who, role):
    svc, life, res = queued
    out = life.complete_approved(res["approval_request_id"], who, role)
    assert out["status"] == "completed" and out["approver"] == who
    assert _bal(svc) == round(12850.00 - 11000, 2)
    assert svc.get_balance("CUST-002", "ACC-2001")["balance"] == round(3100.25 + 11000, 2)
    txn = svc.repository.get_transaction(res["transaction_id"])
    assert txn.status == "COMPLETED" and txn.approval_status == "APPROVED"
    again = life.complete_approved(res["approval_request_id"], who, role)
    assert again["status"] == "error"                                  # cannot be replayed
    assert _bal(svc) == round(12850.00 - 11000, 2)


def test_human_rejection_keeps_funds_in_place(queued):
    svc, life, res = queued
    out = life.reject_pending(res["approval_request_id"], "FRAUD-001", "FRAUD_ANALYST", "beneficiary unknown")
    assert out["status"] == "rejected"
    assert svc.repository.get_transaction(res["transaction_id"]).status == "REJECTED"
    assert _bal(svc) == 12850.00
    assert life.complete_approved(res["approval_request_id"], "ADMIN-001", "ADMIN")["status"] == "error"


def test_tampered_transaction_is_not_executed_after_approval(queued):
    svc, life, res = queued
    txn = svc.repository.get_transaction(res["transaction_id"])
    txn.amount = 11500.0                                              # attacker edits the queued record after approval was requested
    out = life.complete_approved(res["approval_request_id"], "ADMIN-001", "ADMIN")
    assert out["status"] == "blocked" and "Scope mismatch" in out["reason"]
    assert _bal(svc) == 12850.00


def test_expired_request_cannot_be_approved(queued):
    svc, life, res = queued
    rec = get_approval_engine().get_request(res["approval_request_id"])
    rec.expires_at = "2000-01-01T00:00:00+00:00"
    out = life.complete_approved(res["approval_request_id"], "ADMIN-001", "ADMIN")
    assert out["status"] == "blocked"
    assert _bal(svc) == 12850.00


def test_unknown_approval_id():
    life = get_transaction_lifecycle_service()
    assert life.complete_approved("APPR-NOPE", "ADMIN-001", "ADMIN")["status"] == "error"
    assert life.reject_pending("APPR-NOPE", "ADMIN-001", "ADMIN")["status"] == "error"


def test_risk_block_cannot_be_overridden_by_human_approval():
    svc = reset_shared_fintech_service()
    life = get_transaction_lifecycle_service()
    res = life.process_transaction_request("Transfer 12000 dollars from ACC-1002 to ACC-2001", user_context=dict(CTX))
    assert res["status"] == "APPROVAL_REQUIRED"
    out = life.complete_approved(res["approval_request_id"], "ADMIN-001", "ADMIN")
    assert out["status"] == "blocked" and "Risk policy" in out["reason"]
    assert _bal(svc) == 12850.00
    assert svc.repository.get_transaction(res["transaction_id"]).status == "REJECTED"
