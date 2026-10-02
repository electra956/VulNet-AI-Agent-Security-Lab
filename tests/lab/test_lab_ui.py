"""Streamlit AppTest smoke tests: every dashboard page renders without an exception and shows real data."""

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from auth.authentication import get_auth_service

APP = Path(__file__).resolve().parents[2] / "chatbot" / "app.py"
MAIN_PAGES = ["💬 Chat", "💸 Pay", "👤 Profile", "🏦 Account", "💳 Transactions"]
PAGES = ["💬 Chat", "💸 Pay", "👤 Profile", "👥 Users", "🏦 Account", "💳 Transactions", "✅ Approvals", "🤖 Agents", "📚 RAG", "🧠 Memory", "🧰 MCP Tools",
         "🚦 Security Gateway", "⚔️ Attack Lab", "📑 Agent Trace", "📜 Audit", "📄 Reports", "🩺 System Health"]


def _authed_app():
    svc = get_auth_service()
    lg = svc.login("alex_morgan", "Cust001Secure!2026")
    sess = svc.verify_mfa(lg["challenge_id"], lg["mfa_code"])
    sid = sess.session_id if hasattr(sess, "session_id") else sess["session_id"]
    at = AppTest.from_file(str(APP), default_timeout=60)
    at.session_state["active_session_id"] = sid
    return at


def _go(at, page):
    """Main pages live in the radio; everything else is under the 'Other' dropdown."""
    if page in MAIN_PAGES:
        at.sidebar.radio(key="nav_radio").set_value(page).run()
    else:
        at.sidebar.selectbox(key="more_pick").set_value(page).run()
    return at


@pytest.mark.parametrize("page", PAGES)
def test_page_renders(page):
    at = _authed_app().run()
    _go(at, page)
    assert not at.exception, [e.value for e in at.exception]


@pytest.mark.parametrize("asi", [f"ASI{i:02d}" for i in range(1, 11)])
def test_owasp_page_renders_and_launches(asi):
    labels = {"ASI01": "ASI01 · Agent Goal Hijack", "ASI02": "ASI02 · Tool Misuse & Exploitation", "ASI03": "ASI03 · Identity & Privilege Abuse",
              "ASI04": "ASI04 · Agentic Supply Chain", "ASI05": "ASI05 · Unexpected Code Execution", "ASI06": "ASI06 · Memory & Context Poisoning",
              "ASI07": "ASI07 · Insecure Inter-Agent Comms", "ASI08": "ASI08 · Cascading Failures",
              "ASI09": "ASI09 · Human-Agent Trust Exploitation", "ASI10": "ASI10 · Rogue Agents"}
    at = _authed_app().run()
    at.sidebar.selectbox(key="more_pick").set_value(labels[asi]).run()
    assert not at.exception, [e.value for e in at.exception]
    assert asi in at.title[0].value
    launch = next(b for b in at.button if "Launch controlled test" in b.label)
    launch.click().run()
    assert not at.exception, [e.value for e in at.exception]
    assert any("ATTACK" in m.value for m in at.markdown), "result banner must be rendered"


# ---------------------------------------------------------------------------
# Approvals page: a real human decision through the UI
# ---------------------------------------------------------------------------

def _login(username, password):
    svc = get_auth_service()
    lg = svc.login(username, password)
    return svc.verify_mfa(lg["challenge_id"], lg["mfa_code"]).session_id


def _queue_transfer():
    from security.approval_engine import get_approval_engine
    get_approval_engine()._approvals.clear()
    from fintech.service import reset_shared_fintech_service
    from fintech.transaction_lifecycle import get_transaction_lifecycle_service
    svc = reset_shared_fintech_service()
    res = get_transaction_lifecycle_service().process_transaction_request(
        "Transfer 11000 dollars from ACC-1002 to ACC-2001",
        user_context={"user_id": "CUST-001", "role": "customer", "account_ids": ["ACC-1001", "ACC-1002"], "session_id": "S-UI", "request_id": "R-UI"})
    assert res["status"] == "APPROVAL_REQUIRED"
    return svc, res


def _open(sid):
    at = AppTest.from_file(str(APP), default_timeout=60)
    at.session_state["active_session_id"] = sid
    at.run()
    _go(at, "✅ Approvals")
    assert not at.exception, [e.value for e in at.exception]
    return at


def test_admin_approves_through_the_ui_and_the_transfer_executes():
    svc, res = _queue_transfer()
    at = _open(_login("morgan_vance", "Admin001Secure!2026"))
    approve = next(b for b in at.button if "Approve" in b.label)
    approve.click().run()
    assert not at.exception, [e.value for e in at.exception]
    assert svc.repository.get_transaction(res["transaction_id"]).status == "COMPLETED"
    assert svc.get_balance("CUST-001", "ACC-1002")["balance"] == round(12850.00 - 11000, 2)
    from fintech.service import reset_shared_fintech_service
    reset_shared_fintech_service()


def test_customer_sees_the_request_but_has_no_decision_buttons():
    svc, res = _queue_transfer()
    at = _open(_login("alex_morgan", "Cust001Secure!2026"))
    assert not [b for b in at.button if "Approve" in b.label or "Reject" in b.label]
    assert svc.repository.get_transaction(res["transaction_id"]).status == "APPROVAL_REQUIRED"
    from fintech.service import reset_shared_fintech_service
    reset_shared_fintech_service()
