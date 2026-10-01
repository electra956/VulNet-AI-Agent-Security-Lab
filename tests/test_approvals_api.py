"""Approval queue over HTTP: identity comes from the session; customers/AI cannot decide."""

from fastapi.testclient import TestClient

from api.main import app
from fintech.service import reset_shared_fintech_service
from fintech.transaction_lifecycle import get_transaction_lifecycle_service
from security.approval_engine import get_approval_engine

client = TestClient(app)


def _session(u, p):
    lg = client.post("/auth/login", json={"username": u, "password": p}).json()
    return client.post("/auth/mfa/verify", json={"challenge_id": lg["challenge_id"], "code": lg["mfa_code"]}).json()["session_id"]


def _queue():
    get_approval_engine()._approvals.clear()          # the approval queue is process-wide; isolate each test
    svc = reset_shared_fintech_service()
    res = get_transaction_lifecycle_service().process_transaction_request(
        "Transfer 11000 dollars from ACC-1002 to ACC-2001",
        user_context={"user_id": "CUST-001", "role": "customer", "account_ids": ["ACC-1001", "ACC-1002"], "session_id": "S-API", "request_id": "R-API"})
    return svc, res["approval_request_id"], res["transaction_id"]


def test_requires_authentication():
    assert client.get("/approvals", params={"session_id": "NOPE"}).status_code == 401
    assert client.post("/approvals/APPR-1/approve", json={"session_id": "NOPE"}).status_code == 401


def test_customer_sees_own_requests_but_cannot_decide():
    svc, aid, tid = _queue()
    cust = _session("alex_morgan", "Cust001Secure!2026")
    view = client.get("/approvals", params={"session_id": cust}).json()
    assert view["can_decide"] is False and [a["approval_id"] for a in view["approvals"]] == [aid]
    assert client.post(f"/approvals/{aid}/approve", json={"session_id": cust}).status_code == 403
    assert client.post(f"/approvals/{aid}/reject", json={"session_id": cust}).status_code == 403
    assert svc.repository.get_transaction(tid).status == "APPROVAL_REQUIRED"


def test_other_customer_cannot_see_or_decide():
    svc, aid, tid = _queue()
    other = _session("jordan_lee", "Cust002Secure!2026")
    assert client.get("/approvals", params={"session_id": other}).json()["approvals"] == []
    assert client.post(f"/approvals/{aid}/approve", json={"session_id": other}).status_code == 403


def test_support_agent_approves_and_funds_move_exactly_once():
    svc, aid, tid = _queue()
    staff = _session("sam_casey", "Support001Secure!2026")
    r = client.post(f"/approvals/{aid}/approve", json={"session_id": staff}).json()
    assert r["status"] == "completed" and r["approver"] == "SUPPORT-001"
    assert svc.get_balance("CUST-001", "ACC-1002")["balance"] == round(12850.00 - 11000, 2)
    again = client.post(f"/approvals/{aid}/approve", json={"session_id": staff}).json()
    assert again["status"] == "error"
    assert svc.get_balance("CUST-001", "ACC-1002")["balance"] == round(12850.00 - 11000, 2)


def test_fraud_analyst_can_reject_and_unknown_id_404():
    svc, aid, tid = _queue()
    fraud = _session("riley_taylor", "Fraud001Secure!2026")
    assert client.post(f"/approvals/{aid}/reject", json={"session_id": fraud, "reason": "unknown beneficiary"}).json()["status"] == "rejected"
    assert svc.repository.get_transaction(tid).status == "REJECTED"
    assert client.post("/approvals/APPR-NOPE/approve", json={"session_id": fraud}).status_code == 404


def test_compliance_role_is_read_only():
    svc, aid, tid = _queue()
    comp = _session("casey_reyes", "Compliance001Secure!2026")
    assert client.post(f"/approvals/{aid}/approve", json={"session_id": comp}).status_code == 403
