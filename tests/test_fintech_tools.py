"""
VulNet AI Agent Security Lab - Simulated FinTech Tool Ecosystem Tests
Level 2 Step 12: Simulated FinTech Tool Ecosystem

Comprehensive tests verifying:
- All 16 tools across 6 categories (ACCOUNT, PAYMENT, CARD, FRAUD, KYC, SUPPORT)
- Strict object-level ownership checks (BOLA defense)
- High-risk human approval gates
- Role-based access control (RBAC)
- Audit telemetry logging for every tool invocation
"""

import pytest
from mcp_server.server import MCPServer
from security.security_controller import SecurityController
from chatbot.sessions.session_manager import SessionContext
from auth.roles import Role


@pytest.fixture
def mcp():
    """Return an MCP server with security controller attached."""
    sec = SecurityController(mode="secure")
    server = MCPServer(mode="secure", security_controller=sec)
    return server, sec


# =============================================================================
# 1. ACCOUNT CATEGORY TESTS
# =============================================================================
def test_get_account_balance(mcp):
    server, sec = mcp
    # Authorized access
    res = server.execute_tool(
        "get_account_balance",
        caller_role="CUSTOMER",
        customer_id="CUST-001",
        account_id="ACC-1001"
    )
    assert res["status"] == "success"
    assert res["result"]["account_id"] == "ACC-1001"
    assert res["result"]["balance"] > 0

    # Cross-customer ownership violation (CUST-001 attempting ACC-2001)
    res_bola = server.execute_tool(
        "get_account_balance",
        caller_role="CUSTOMER",
        customer_id="CUST-001",
        account_id="ACC-2001"
    )
    assert res_bola["status"] == "blocked"
    assert "does not own account" in res_bola["reason"].lower()

    # Verify audit events
    events = sec.get_events()
    assert any(e["event_type"] == "TOOL_EXECUTION_COMPLETED" for e in events)
    assert any(e["event_type"] == "TOOL_ACCESS_DENIED" for e in events)


def test_get_account_status(mcp):
    server, _ = mcp
    res = server.execute_tool(
        "get_account_status",
        caller_role="CUSTOMER",
        customer_id="CUST-001",
        account_id="ACC-1001"
    )
    assert res["status"] == "success"
    assert res["result"]["status"] == "ACTIVE"
    assert res["result"]["account_type"] == "Premier Checking"


def test_get_customer_profile(mcp):
    server, _ = mcp
    res = server.execute_tool(
        "get_customer_profile",
        caller_role="CUSTOMER",
        customer_id="CUST-001"
    )
    assert res["status"] == "success"
    assert res["result"]["name"] == "Alex Morgan"
    assert "ACC-1001" in res["result"]["account_ids"]


def test_get_transaction_history(mcp):
    server, _ = mcp
    res = server.execute_tool(
        "get_transaction_history",
        caller_role="CUSTOMER",
        customer_id="CUST-001",
        account_id="ACC-1001",
        limit=5
    )
    assert res["status"] == "success"
    assert res["result"]["account_id"] == "ACC-1001"
    assert len(res["result"]["transactions"]) >= 1


# =============================================================================
# 2. PAYMENT CATEGORY TESTS
# =============================================================================
def test_create_payment_approval_and_ownership(mcp):
    server, sec = mcp

    # 1. Blocked without human approval (High Risk)
    res_unauth = server.execute_tool(
        "create_payment",
        caller_role="CUSTOMER",
        from_account="ACC-1001",
        to_account="ACC-2001",
        amount=100.0,
        user_authorized=False
    )
    assert res_unauth["status"] == "blocked"
    assert "requires explicit human authorization" in res_unauth["reason"].lower()

    # 2. Blocked if customer doesn't own source account
    res_bola = server.execute_tool(
        "create_payment",
        caller_role="CUSTOMER",
        customer_id="CUST-001",
        from_account="ACC-2001",
        to_account="ACC-1001",
        amount=50.0,
        user_authorized=True
    )
    assert res_bola["status"] == "blocked"
    assert "does not own account" in res_bola["reason"].lower()

    # 3. Successful simulated transfer with approval
    res_success = server.execute_tool(
        "create_payment",
        caller_role="CUSTOMER",
        customer_id="CUST-001",
        from_account="ACC-1001",
        to_account="ACC-2001",
        amount=50.0,
        user_authorized=True
    )
    assert res_success["status"] == "success"
    assert res_success["result"]["status"] == "SIMULATED_TRANSFERRED"
    assert res_success["result"]["real_funds_moved"] is False


def test_schedule_payment(mcp):
    server, _ = mcp
    res = server.execute_tool(
        "schedule_payment",
        caller_role="CUSTOMER",
        customer_id="CUST-001",
        from_account="ACC-1001",
        to_account="ACC-2001",
        amount=120.0,
        execution_date="2026-10-01"
    )
    assert res["status"] == "success"
    assert res["result"]["status"] == "SCHEDULED"
    assert res["result"]["amount"] == 120.0


def test_cancel_payment(mcp):
    server, _ = mcp
    # First schedule
    sched = server.execute_tool(
        "schedule_payment",
        caller_role="CUSTOMER",
        customer_id="CUST-001",
        from_account="ACC-1001",
        to_account="ACC-2001",
        amount=75.0,
        execution_date="2026-10-05"
    )
    sched_id = sched["result"]["schedule_id"]

    # Cancel payment
    res_cancel = server.execute_tool(
        "cancel_payment",
        caller_role="CUSTOMER",
        customer_id="CUST-001",
        payment_id=sched_id
    )
    assert res_cancel["status"] == "success"
    assert res_cancel["result"]["status"] == "CANCELLED"


# =============================================================================
# 3. CARD CATEGORY TESTS
# =============================================================================
def test_get_card_status(mcp):
    server, _ = mcp
    res = server.execute_tool(
        "get_card_status",
        caller_role="CUSTOMER",
        customer_id="CUST-001",
        card_id="CARD-1001"
    )
    assert res["status"] == "success"
    assert res["result"]["card_id"] == "CARD-1001"
    assert res["result"]["status"] == "ACTIVE"


def test_freeze_and_unfreeze_card(mcp):
    server, sec = mcp

    # Cross-customer card freeze attempt
    res_bola = server.execute_tool(
        "freeze_card",
        caller_role="CUSTOMER",
        customer_id="CUST-001",
        card_id="CARD-2001",
        user_authorized=True
    )
    assert res_bola["status"] == "blocked"
    assert "does not own card" in res_bola["reason"].lower()

    # Freeze card without approval -> blocked
    res_unauth = server.execute_tool(
        "freeze_card",
        caller_role="CUSTOMER",
        customer_id="CUST-001",
        card_id="CARD-1001",
        user_authorized=False
    )
    assert res_unauth["status"] == "blocked"

    # Freeze card with approval -> success
    res_freeze = server.execute_tool(
        "freeze_card",
        caller_role="CUSTOMER",
        customer_id="CUST-001",
        card_id="CARD-1001",
        user_authorized=True,
        reason="Suspicious SMS alert"
    )
    assert res_freeze["status"] == "success"
    assert res_freeze["result"]["status"] == "FROZEN"

    # Unfreeze card
    res_unfreeze = server.execute_tool(
        "unfreeze_card",
        caller_role="CUSTOMER",
        customer_id="CUST-001",
        card_id="CARD-1001",
        user_authorized=True
    )
    assert res_unfreeze["status"] == "success"
    assert res_unfreeze["result"]["status"] == "ACTIVE"


# =============================================================================
# 4. FRAUD CATEGORY TESTS
# =============================================================================
def test_check_transaction_risk(mcp):
    server, _ = mcp
    # Small amount -> LOW
    res_low = server.execute_tool(
        "check_transaction_risk",
        caller_role="FRAUD_ANALYST",
        transaction_id="TXN-10002",
        amount=50.0
    )
    assert res_low["status"] == "success"
    assert res_low["result"]["risk_tier"] == "LOW"

    # Large amount -> HIGH
    res_high = server.execute_tool(
        "check_transaction_risk",
        caller_role="FRAUD_ANALYST",
        transaction_id="TXN-10001",
        amount=25000.0
    )
    assert res_high["status"] == "success"
    assert res_high["result"]["risk_tier"] == "HIGH"


def test_flag_transaction_and_get_fraud_case(mcp):
    server, _ = mcp
    res_flag = server.execute_tool(
        "flag_transaction",
        caller_role="FRAUD_ANALYST",
        transaction_id="TXN-10001",
        suspicion_reason="Abnormal transfer volume to new payee"
    )
    assert res_flag["status"] == "success"
    case_id = res_flag["result"]["case_id"]

    res_case = server.execute_tool(
        "get_fraud_case",
        caller_role="FRAUD_ANALYST",
        case_id=case_id
    )
    assert res_case["status"] == "success"
    assert res_case["result"]["transaction_id"] == "TXN-10001"
    assert res_case["result"]["status"] == "UNDER_REVIEW"


# =============================================================================
# 5. KYC CATEGORY TESTS
# =============================================================================
def test_get_kyc_status_and_verification(mcp):
    server, _ = mcp
    res_status = server.execute_tool(
        "get_kyc_status",
        caller_role="CUSTOMER",
        customer_id="CUST-001"
    )
    assert res_status["status"] == "success"
    assert res_status["result"]["kyc_status"] == "VERIFIED"

    res_verify = server.execute_tool(
        "verify_identity_simulated",
        caller_role="COMPLIANCE_ANALYST",
        customer_id="CUST-002",
        document_type="PASSPORT",
        document_number="A12345678"
    )
    assert res_verify["status"] == "success"
    assert res_verify["result"]["verification_status"] == "PASSED"


# =============================================================================
# 6. SUPPORT CATEGORY TESTS
# =============================================================================
def test_create_support_ticket_and_notification(mcp):
    server, _ = mcp
    res_ticket = server.execute_tool(
        "create_support_ticket",
        caller_role="CUSTOMER",
        customer_id="CUST-001",
        subject="Statement clarification",
        description="Need explanation on utility charge",
        priority="LOW"
    )
    assert res_ticket["status"] == "success"
    assert res_ticket["result"]["status"] == "OPEN"

    res_notif = server.execute_tool(
        "send_simulated_notification",
        caller_role="SUPPORT_AGENT",
        customer_id="CUST-001",
        message="Your support ticket has been received.",
        channel="SMS"
    )
    assert res_notif["status"] == "success"
    assert res_notif["result"]["channel"] == "SMS"


# =============================================================================
# 7. SESSION CONTEXT INTEGRATION & OWNERSHIP
# =============================================================================
def test_session_context_automatic_customer_id(mcp):
    server, sec = mcp
    session = SessionContext(
        session_id="SESS-CUST-001",
        request_id="REQ-001",
        user_id="CUST-001",
        role=Role.CUSTOMER.value,
        account_ids=["ACC-1001"],
        created_at="2026-09-16T12:00:00Z",
        conversation_id="CONV-001"
    )

    # Calling tool using SessionContext automatically binds customer_id="CUST-001"
    res = server.execute_tool("get_account_balance", caller_role=session, account_id="ACC-1001")
    assert res["status"] == "success"
    assert res["result"]["account_id"] == "ACC-1001"

    # Attempting to access CUST-002's account with session CUST-001
    res_bola = server.execute_tool("get_account_balance", caller_role=session, account_id="ACC-2001")
    assert res_bola["status"] == "blocked"
    assert "does not own account" in res_bola["reason"].lower()
