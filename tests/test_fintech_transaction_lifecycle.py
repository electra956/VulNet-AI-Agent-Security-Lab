"""
Tests for Step 17 — Complete FinTech Transaction Lifecycle.

Covers:
1. Normal low-risk transaction (₹500, low risk, completed)
2. High-risk transaction (₹50,000, high risk, approval required)
3. Human approval required (AI cannot self-approve, approval pending)
4. Unauthorized account (CUST-001 operating on CUST-002 account -> REJECTED)
5. Invalid amount (<= 0 -> REJECTED / validation error)
6. Invalid destination account (same source and destination -> REJECTED)
7. Unknown user (fails authentication/identity resolution)
8. Missing authentication (no user context -> fails)
9. MCP authorization failure (direct MCP call unauthorized -> DENY)
10. Tool execution success (simulated balance updated, state completed)
11. Tool execution blocked (high risk blocked from executing tool)
12. Audit creation (audit events logged to audit logger)
13. Transaction state transitions (explicit state machine validation)
"""

import pytest
import os
from auth.authentication import AuthenticationService
from fintech.models import (
    TransactionStatus,
    Transaction,
    VALID_STATE_TRANSITIONS,
    InvalidStateTransitionError,
    TransactionValidationError,
)
from fintech.repository import FintechRepository
from fintech.service import FintechService
from fintech.transaction_lifecycle import TransactionLifecycleService, get_transaction_lifecycle_service
from mcp_server.server import MCPServer
from security.approval_engine import ApprovalEngine
from observability.audit import AuditLogger
from observability.trace import RequestTracer
from chatbot.sessions.session_manager import SessionManager


@pytest.fixture
def clean_repo():
    repo = FintechRepository()
    # Reset CUST-001 balance to initial 1500.00
    repo.update_account_balance("ACC-1001", 1500.00)
    repo.update_account_balance("ACC-2001", 3250.00)
    return repo


@pytest.fixture
def lifecycle_service(clean_repo):
    service = TransactionLifecycleService(fintech_repo=clean_repo)
    return service


# ==============================================================================
# TEST 1: Normal Low-Risk Transaction
# ==============================================================================
def test_normal_low_risk_transaction(lifecycle_service, clean_repo):
    """
    Scenario:
    User: CUST-001
    Source: ACC-1001
    Destination: ACC-2001
    Amount: ₹500

    Expected:
    AUTHENTICATED -> AUTHORIZED -> LOW RISK -> NO HUMAN APPROVAL
    -> MCP ALLOWED -> SIMULATED TOOL EXECUTES -> TRANSACTION COMPLETED -> AUDIT CREATED
    """
    user_context = {
        "user_id": "CUST-001",
        "username": "alice",
        "role": "customer",
        "accounts": ["ACC-1001", "ACC-1002"]
    }
    
    result = lifecycle_service.process_transaction_request(
        user_message="Transfer ₹500 from ACC-1001 to ACC-2001",
        user_context=user_context,
        session_id="sess-normal-001",
        request_id="req-normal-001"
    )

    assert result["success"] is True
    assert result["status"] == TransactionStatus.COMPLETED.value
    assert result["risk_level"] == "LOW"
    assert result["requires_approval"] is False
    assert result["mcp_execution_status"] == "SUCCESS"
    assert result["transaction_id"].startswith("TXN-")
    assert result["audit_recorded"] is True
    assert result["trace_recorded"] is True
    
    # Check balance was updated deterministically
    acc_1001 = clean_repo.get_account("ACC-1001")
    acc_2001 = clean_repo.get_account("ACC-2001")
    assert acc_1001.balance == 1000.00  # 1500 - 500
    assert acc_2001.balance == 3750.00  # 3250 + 500


# ==============================================================================
# TEST 2 & 3: High-Risk Transaction & Human Approval Required
# ==============================================================================
def test_high_risk_transaction_requires_approval(lifecycle_service, clean_repo):
    """
    Scenario:
    CUST-001 transfer ₹50,000 to ACC-2001

    Expected:
    AUTHENTICATED -> AUTHORIZED -> HIGH RISK -> APPROVAL REQUIRED
    -> MCP/tool execution MUST NOT occur -> transaction remains APPROVAL_REQUIRED
    -> AI agent must NEVER approve its own transaction.
    """
    # Temporarily give user enough funds so it doesn't fail purely on balance
    clean_repo.update_account_balance("ACC-1001", 100000.00)

    user_context = {
        "user_id": "CUST-001",
        "username": "alice",
        "role": "customer",
        "accounts": ["ACC-1001"]
    }

    result = lifecycle_service.process_transaction_request(
        user_message="Transfer ₹50000 from ACC-1001 to ACC-2001",
        user_context=user_context,
        session_id="sess-highrisk-001",
        request_id="req-highrisk-001"
    )

    assert result["success"] is True
    assert result["status"] == TransactionStatus.APPROVAL_REQUIRED.value
    assert result["risk_level"] in ("HIGH", "CRITICAL")
    assert result["requires_approval"] is True
    assert result["approval_status"] == "PENDING"
    assert result["mcp_execution_status"] == "BLOCKED_PENDING_APPROVAL"
    assert result["approval_request_id"] is not None

    # Balance must NOT be deducted
    acc_1001 = clean_repo.get_account("ACC-1001")
    assert acc_1001.balance == 100000.00


# ==============================================================================
# TEST 3: Human Approval Required & Agent Cannot Self-Approve
# ==============================================================================
def test_human_approval_required(lifecycle_service, clean_repo):
    """
    Scenario:
    A high-risk transaction generates an approval request in the approval queue.
    The AI Agent CANNOT self-approve.
    When approved externally by human authority (user_authorized=True), execution proceeds.
    """
    clean_repo.update_account_balance("ACC-1001", 100000.00)

    user_context = {
        "user_id": "CUST-001",
        "username": "alice",
        "role": "customer",
        "accounts": ["ACC-1001"]
    }

    # Step A: AI Agent attempt without human approval -> APPROVAL_REQUIRED
    res1 = lifecycle_service.process_transaction_request(
        user_message="Transfer ₹50000 from ACC-1001 to ACC-2001",
        user_context=user_context,
        session_id="sess-approval-001",
        request_id="req-approval-001",
        user_authorized=False
    )
    assert res1["status"] == TransactionStatus.APPROVAL_REQUIRED.value
    assert res1["requires_approval"] is True
    approval_id = res1["approval_request_id"]
    assert approval_id is not None

    # Step B: Human approves in ApprovalEngine
    app_engine = lifecycle_service.approval_engine
    approve_res = app_engine.approve(
        approval_id=approval_id,
        approver_id="admin_01",
        approver_role="ADMIN",
        is_ai_caller=False
    )
    assert approve_res["status"] == "success"
    assert approve_res["decision"] == "APPROVED"

    # Step C: Re-invoking with external human authorization proceeds to completion
    res2 = lifecycle_service.process_transaction_request(
        user_message="Transfer ₹50000 from ACC-1001 to ACC-2001",
        user_context=user_context,
        session_id="sess-approval-001",
        request_id="req-approval-002",
        user_authorized=True
    )
    assert res2["status"] == TransactionStatus.COMPLETED.value
    assert res2["success"] is True
    assert res2["mcp_execution_status"] == "SUCCESS"


# ==============================================================================
# TEST 4: Unauthorized Account
# ==============================================================================
def test_unauthorized_account_rejected(lifecycle_service, clean_repo):
    """
    Scenario:
    CUST-001 attempts to operate on ACC-2001 owned by CUST-002.

    Expected:
    AUTHENTICATION = PASS
    AUTHORIZATION = FAIL
    Transaction tool MUST NOT execute.
    Expected final state: REJECTED
    Audit event recorded.
    """
    user_context = {
        "user_id": "CUST-001",
        "username": "alice",
        "role": "customer",
        "accounts": ["ACC-1001"]
    }

    result = lifecycle_service.process_transaction_request(
        user_message="Transfer ₹500 from ACC-2001 to ACC-1001",
        user_context=user_context,
        session_id="sess-unauth-001",
        request_id="req-unauth-001"
    )

    assert result["success"] is False
    assert result["status"] == TransactionStatus.REJECTED.value
    assert "ownership" in result["error"].lower() or "not authorized" in result["error"].lower()
    assert result["mcp_execution_status"] == "NOT_CALLED"
    assert result["audit_recorded"] is True

    # Balances must remain unchanged
    acc_2001 = clean_repo.get_account("ACC-2001")
    assert acc_2001.balance == 3250.00


# ==============================================================================
# TEST 5: Invalid Amount
# ==============================================================================
def test_invalid_amount_rejected(lifecycle_service):
    """
    Scenario: Amount <= 0
    """
    user_context = {
        "user_id": "CUST-001",
        "username": "alice",
        "role": "customer",
        "accounts": ["ACC-1001"]
    }

    result = lifecycle_service.process_transaction_request(
        user_message="Transfer ₹-50 from ACC-1001 to ACC-2001",
        user_context=user_context,
        session_id="sess-inv-amt-001",
        request_id="req-inv-amt-001"
    )

    assert result["success"] is False
    assert result["status"] == TransactionStatus.REJECTED.value
    assert "positive" in result["error"].lower() or "invalid" in result["error"].lower()


# ==============================================================================
# TEST 6: Invalid Destination Account
# ==============================================================================
def test_invalid_destination_account_rejected(lifecycle_service):
    """
    Scenario: Source and destination are identical
    """
    user_context = {
        "user_id": "CUST-001",
        "username": "alice",
        "role": "customer",
        "accounts": ["ACC-1001"]
    }

    result = lifecycle_service.process_transaction_request(
        user_message="Transfer ₹100 from ACC-1001 to ACC-1001",
        user_context=user_context,
        session_id="sess-same-acc-001",
        request_id="req-same-acc-001"
    )

    assert result["success"] is False
    assert result["status"] == TransactionStatus.REJECTED.value
    assert "cannot be the same" in result["error"].lower()


# ==============================================================================
# TEST 7: Unknown User
# ==============================================================================
def test_unknown_user_rejected(lifecycle_service):
    """
    Scenario: User context indicates an unknown or nonexistent user
    """
    user_context = {
        "user_id": "UNKNOWN-999",
        "username": "ghost",
        "role": "customer",
        "accounts": []
    }

    result = lifecycle_service.process_transaction_request(
        user_message="Transfer ₹100 from ACC-1001 to ACC-2001",
        user_context=user_context,
        session_id="sess-ghost-001",
        request_id="req-ghost-001"
    )

    assert result["success"] is False
    assert result["status"] == TransactionStatus.REJECTED.value
    assert "user" in result["error"].lower() or "ownership" in result["error"].lower()


# ==============================================================================
# TEST 8: Missing Authentication
# ==============================================================================
def test_missing_authentication_rejected(lifecycle_service):
    """
    Scenario: user_context is missing or unauthenticated
    """
    result = lifecycle_service.process_transaction_request(
        user_message="Transfer ₹500 from ACC-1001 to ACC-2001",
        user_context=None,
        session_id="sess-noauth-001",
        request_id="req-noauth-001"
    )

    assert result["success"] is False
    assert result["status"] == TransactionStatus.REJECTED.value
    assert "unauthenticated" in result["error"].lower() or "missing" in result["error"].lower()


# ==============================================================================
# TEST 9: MCP Authorization Failure
# ==============================================================================
def test_mcp_authorization_failure(clean_repo):
    """
    Scenario:
    Direct call to MCP tool gateway with mismatched ownership or unauthorized user.
    MCP independently validates:
      - authenticated user
      - role
      - permission
      - tool name
      - arguments
    """
    mcp_server = MCPServer(mode="secure")

    # User CUST-002 attempting to transfer from ACC-1001 (owned by CUST-001)
    response = mcp_server.execute_tool(
        tool_name="create_simulated_transaction",
        caller_role="CUSTOMER",
        customer_id="CUST-002",
        from_account="ACC-1001",
        to_account="ACC-2001",
        amount=200.0,
        currency="INR"
    )

    assert response["status"] in ("blocked", "error")
    assert "unauthorized" in response.get("reason", "").lower() or "ownership" in response.get("reason", "").lower() or "deny" in response.get("decision", "").lower()


# ==============================================================================
# TEST 10: Tool Execution Success
# ==============================================================================
def test_tool_execution_success(clean_repo):
    """
    Scenario:
    Authorized customer executes create_simulated_transaction through MCP.
    """
    mcp_server = MCPServer(mode="secure")

    response = mcp_server.execute_tool(
        tool_name="create_simulated_transaction",
        caller_role="CUSTOMER",
        customer_id="CUST-001",
        from_account="ACC-1001",
        to_account="ACC-2001",
        amount=100.0,
        currency="INR"
    )

    assert response["status"] == "success"
    result = response["result"]
    assert result["status"] == "COMPLETED"
    assert result["from_account"] == "ACC-1001"
    assert result["to_account"] == "ACC-2001"


# ==============================================================================
# TEST 11: Tool Execution Blocked
# ==============================================================================
def test_tool_execution_blocked_on_excessive_risk(clean_repo):
    """
    Scenario:
    Tool execution blocked when amount triggers high risk without prior approval.
    """
    mcp_server = MCPServer(mode="secure")

    # Attempt ₹60,000 transfer without approval flag
    response = mcp_server.execute_tool(
        tool_name="create_simulated_transaction",
        caller_role="CUSTOMER",
        customer_id="CUST-001",
        from_account="ACC-1001",
        to_account="ACC-2001",
        amount=60000.0,
        currency="INR",
        user_authorized=False
    )

    assert response["status"] == "blocked"
    assert "approval" in response.get("reason", "").lower() or response.get("decision") == "DENY"


# ==============================================================================
# TEST 12: Audit Creation
# ==============================================================================
def test_audit_creation_on_transaction(lifecycle_service):
    """
    Scenario:
    Every transaction generates structured audit log entries.
    """
    user_context = {
        "user_id": "CUST-001",
        "username": "alice",
        "role": "customer",
        "accounts": ["ACC-1001"]
    }

    result = lifecycle_service.process_transaction_request(
        user_message="Transfer ₹150 from ACC-1001 to ACC-2001",
        user_context=user_context,
        session_id="sess-audit-001",
        request_id="req-audit-001"
    )

    assert result["audit_recorded"] is True

    # Verify audit log exists on filesystem
    audit_file = os.path.join(os.path.dirname(__file__), "..", "logs", "audit.jsonl")
    assert os.path.exists(audit_file)


# ==============================================================================
# TEST 13: Transaction State Transitions
# ==============================================================================
def test_transaction_state_transitions():
    """
    Scenario:
    Validate explicit state transitions:
    PENDING -> PROCESSING -> COMPLETED
    PENDING -> APPROVAL_REQUIRED -> APPROVED -> PROCESSING -> COMPLETED
    PENDING -> REJECTED
    Invalid transitions raise InvalidStateTransitionError.
    """
    txn = Transaction(
        transaction_id="TXN-TEST-001",
        request_id="REQ-TEST",
        session_id="SESS-TEST",
        user_id="CUST-001",
        source_account_id="ACC-1001",
        destination_account_id="ACC-2001",
        amount=500.0,
        currency="INR",
        status=TransactionStatus.PENDING
    )

    # Valid: PENDING -> PROCESSING
    txn.transition_to(TransactionStatus.PROCESSING, "Beginning processing")
    assert txn.status == TransactionStatus.PROCESSING

    # Valid: PROCESSING -> COMPLETED
    txn.transition_to(TransactionStatus.COMPLETED, "Transfer complete")
    assert txn.status == TransactionStatus.COMPLETED

    # Invalid: COMPLETED -> PROCESSING
    with pytest.raises(InvalidStateTransitionError):
        txn.transition_to(TransactionStatus.PROCESSING, "Cannot re-process")

    # High-risk path test
    txn2 = Transaction(
        transaction_id="TXN-TEST-002",
        request_id="REQ-TEST-2",
        session_id="SESS-TEST-2",
        user_id="CUST-001",
        source_account_id="ACC-1001",
        destination_account_id="ACC-2001",
        amount=50000.0,
        currency="INR",
        status=TransactionStatus.PENDING
    )
    
    # Valid: PENDING -> APPROVAL_REQUIRED
    txn2.transition_to(TransactionStatus.APPROVAL_REQUIRED, "High risk detected")
    assert txn2.status == TransactionStatus.APPROVAL_REQUIRED

    # Valid: APPROVAL_REQUIRED -> APPROVED
    txn2.transition_to(TransactionStatus.APPROVED, "Human admin approved")
    assert txn2.status == TransactionStatus.APPROVED

    # Valid: APPROVED -> PROCESSING
    txn2.transition_to(TransactionStatus.PROCESSING, "Processing approved transfer")
    assert txn2.status == TransactionStatus.PROCESSING

    # Valid: PROCESSING -> COMPLETED
    txn2.transition_to(TransactionStatus.COMPLETED, "Completed")
    assert txn2.status == TransactionStatus.COMPLETED
