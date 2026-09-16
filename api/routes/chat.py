"""
VulNet FinTech AI Agent Security Lab - Chat Route.
POST /chat
"""

from datetime import datetime
import logging
import re
import time
from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException, status

from api.schemas import ChatRequest, ChatResponse
from agents.orchestrator import AgentOrchestrator
from chatbot.sessions.session_manager import SessionManager, Session, get_shared_session_manager
from auth.authentication import get_auth_service
from auth.models import UnauthorizedError
from fintech.service import FintechService
from fintech.models import (
    AccountNotFoundError,
    CustomerNotFoundError,
    UnauthorizedAccessError,
)

logger = logging.getLogger("vulnet.api.chat")
router = APIRouter(tags=["Chat"])

# Service singletons for the API layer
_fintech_service = FintechService()
_orchestrators = {
    "secure": AgentOrchestrator(mode="secure"),
    "vulnerable": AgentOrchestrator(mode="vulnerable"),
}


def get_session_manager() -> SessionManager:
    return get_shared_session_manager()


def get_fintech_service() -> FintechService:
    return _fintech_service


def get_orchestrator(mode: str) -> AgentOrchestrator:
    m = mode.lower()
    return _orchestrators.get(m, _orchestrators["secure"])


def is_greeting(message: str) -> bool:
    greetings = {
        "hi", "hello", "hey", "hii", "hiii", "helo",
        "good morning", "good afternoon", "good evening",
        "how are you", "what's up", "whats up"
    }
    return message.lower().strip() in greetings


def is_balance_query(message: str) -> bool:
    cleaned = message.lower().strip()
    patterns = [
        "what is my balance", "what's my balance", "check my balance",
        "check balance", "my balance", "account balance", "show balance",
        "current balance", "how much money", "view balance", "balance inquiry",
        "get balance", "balance for account", "balance of account",
        "what is the balance", "what's the balance", "balance for", "balance of"
    ]
    return any(p in cleaned for p in patterns)


def is_transaction_query(message: str) -> bool:
    cleaned = message.lower().strip()
    patterns = [
        "recent transactions", "show transactions", "transaction history",
        "my transactions", "account transactions", "past transactions",
        "view transactions", "show recent transactions", "list transactions"
    ]
    return any(p in cleaned for p in patterns)


from auth.authorization import (
    authorize_resource_access,
    authorize_action,
    PermissionDeniedError,
    ResourceAccessDeniedError,
)


def execute_balance_query(
    user_input: str,
    customer_id: str,
    default_account_id: str,
    req_id: str,
    user_role: str = "CUSTOMER"
) -> str:
    """Query balance directly from simulated domain service with external RBAC and ownership authorization."""
    service = get_fintech_service()

    # Detect if another customer's data was requested (e.g. CUST-002)
    match_cust = re.search(r"\b(CUST-\d{3})\b", user_input, re.IGNORECASE)
    if match_cust:
        target_cust = match_cust.group(1).upper()
        try:
            authorize_resource_access(
                user_id=customer_id,
                role=user_role,
                resource_type="customer_history",
                resource_id=target_cust,
                fintech_service=service
            )
        except (ResourceAccessDeniedError, PermissionDeniedError) as exc:
            return (
                f"### 🛡️ FinTech Security Alert: Unauthorized Customer Access [ASI03]\n\n"
                f"**Request ID:** `{req_id}` &bull; **Target Customer:** `{target_cust}`\n\n"
                f"BLOCKED: {str(exc)}"
            )

    match = re.search(r"\b(ACC-\d{4})\b", user_input, re.IGNORECASE)
    target_account = match.group(1).upper() if match else default_account_id

    try:
        authorize_resource_access(
            user_id=customer_id,
            role=user_role,
            resource_type="account",
            resource_id=target_account,
            fintech_service=service
        )
        balance_data = service.get_balance(customer_id, target_account)
        return (
            f"### 🏦 Account Balance Summary\n\n"
            f"**Request ID:** `{req_id}` &bull; **Data Source:** `Simulated FinTech Domain Service`\n\n"
            f"- 👤 **Customer:** `{customer_id}`\n"
            f"- 💳 **Account:** `{balance_data['account_id']}` ({balance_data['account_type']})\n"
            f"- 💵 **Current Available Balance:** `${balance_data['balance']:,.2f} {balance_data['currency']}`\n"
            f"- ⚡ **Status:** `{balance_data['status']}`"
        )
    except (UnauthorizedAccessError, ResourceAccessDeniedError, PermissionDeniedError) as exc:
        return (
            f"### 🛡️ FinTech Security Alert: Unauthorized Account Access [ASI03]\n\n"
            f"**Request ID:** `{req_id}` &bull; **Target Account:** `{target_account}`\n\n"
            f"BLOCKED: Security Violation: Customer '{customer_id}' is not authorized to access account '{target_account}'.\n\n"
            f"FinTech Invariant Enforced: A customer can only access accounts they own."
        )
    except AccountNotFoundError:
        return f"### ⚠️ Account Not Found: `{target_account}`"
    except Exception as exc:
        logger.error("Error in balance query: %s", type(exc).__name__)
        return "An error occurred while retrieving balance."


def execute_transaction_query(
    user_input: str,
    customer_id: str,
    default_account_id: str,
    req_id: str,
    user_role: str = "CUSTOMER"
) -> str:
    """Query transaction history directly from simulated domain service with external RBAC and ownership authorization."""
    service = get_fintech_service()

    # Detect if another customer's data was requested (e.g. CUST-002)
    match_cust = re.search(r"\b(CUST-\d{3})\b", user_input, re.IGNORECASE)
    if match_cust:
        target_cust = match_cust.group(1).upper()
        try:
            authorize_resource_access(
                user_id=customer_id,
                role=user_role,
                resource_type="customer_history",
                resource_id=target_cust,
                fintech_service=service
            )
        except (ResourceAccessDeniedError, PermissionDeniedError) as exc:
            return (
                f"### 🛡️ FinTech Security Alert: Unauthorized Transaction History Access [ASI03]\n\n"
                f"**Request ID:** `{req_id}` &bull; **Target Customer:** `{target_cust}`\n\n"
                f"BLOCKED: {str(exc)}"
            )

    match = re.search(r"\b(ACC-\d{4})\b", user_input, re.IGNORECASE)
    target_account = match.group(1).upper() if match else default_account_id

    try:
        authorize_resource_access(
            user_id=customer_id,
            role=user_role,
            resource_type="account",
            resource_id=target_account,
            fintech_service=service
        )
        txns = service.get_transaction_history(customer_id, target_account)
        lines = [
            f"### 📜 Recent Transaction History",
            f"**Request ID:** `{req_id}` &bull; **Account:** `{target_account}` &bull; **Data Source:** `Simulated FinTech Domain Service`\n"
        ]
        if not txns:
            lines.append(f"*No transactions found for account `{target_account}`.*")
        else:
            for t in txns:
                sign = "+" if t.destination_account == target_account else "-"
                lines.append(
                    f"- **{t.transaction_id}** &bull; `{sign}${abs(t.amount):,.2f} {t.currency}` &bull; {t.description} "
                    f"({t.timestamp[:10]}) &bull; Status: `{t.status}`"
                )
        return "\n".join(lines)
    except (UnauthorizedAccessError, ResourceAccessDeniedError, PermissionDeniedError) as exc:
        return (
            f"### 🛡️ FinTech Security Alert: Unauthorized Transaction History Access [ASI03]\n\n"
            f"**Request ID:** `{req_id}` &bull; **Target Account:** `{target_account}`\n\n"
            f"BLOCKED: Security Violation: Customer '{customer_id}' is not authorized to access transactions for account '{target_account}'."
        )
    except AccountNotFoundError:
        return f"### ⚠️ Account Not Found: `{target_account}`"
    except Exception as exc:
        logger.error("Error in transaction query: %s", type(exc).__name__)
        return "An error occurred while retrieving transaction history."



@router.post("/chat", response_model=ChatResponse)
def post_chat(request: ChatRequest) -> ChatResponse:
    """
    Process conversational request through the FinTech AI Agent gateway.
    Handles perimeter security evaluation, context correlation, direct banking inquiries,
    and multi-agent orchestration.
    """
    start_time = time.perf_counter()
    mgr = get_session_manager()
    req_id = mgr.generate_request_id()
    mode = (request.mode or "secure").lower()

    # Step 0: Authentication Verification (Reject Unauthenticated Requests)
    auth_service = get_auth_service()
    try:
        auth_session = auth_service.authenticate_request(request.session_id)
    except UnauthorizedError as exc:
        logger.warning("Unauthenticated /chat access rejected [Req: %s]: %s", req_id, str(exc))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication required: {str(exc)}"
        )

    user_id = auth_session.user_id
    session_id = auth_session.session_id

    # Step 1: Session lookup or initialization
    session: Optional[Session] = mgr.get_session(session_id)
    if not session:
        session = mgr.create_session(user_id=user_id, session_id=session_id)

    # Step 2: Create structured session context
    session_ctx = session.create_request_context(request_id=req_id)
    session.add_message(role="user", content=request.message, request_id=req_id)

    orchestrator = get_orchestrator(mode)
    default_acct = session.customer_context.account_id

    # Step 3: Security Controller perimeter check at Step 0
    sec_eval = orchestrator.security.evaluate_request(request.message, session_context=session_ctx)
    is_blocked = (sec_eval.get("blocked", False) or sec_eval.get("decision") == "BLOCK") and mode == "secure"

    if is_blocked:
        scenario = sec_eval.get("scenario", "ASI01 - Goal Hijack")
        reason = sec_eval.get("message") or sec_eval.get("reason", "Request blocked by Security Controller.")
        pattern = sec_eval.get("metadata", {}).get("matched_pattern", "Threat Signature")

        category = sec_eval.get("category", "")
        if "ASI03" in scenario or category == "ASI03" or "account" in reason.lower() or "cross-customer" in reason.lower():
            extra_detail = "\n\nBLOCKED: Security Violation: Unauthorized Account Access / Cross-Customer Access.\nFinTech Invariant Enforced: A customer can only access accounts they own."
        else:
            extra_detail = "\n\nBLOCKED: Request rejected by AI Security Gateway perimeter policy."

        blocked_response = (
            f"### 🛡️ Security Alert: Financial Request Blocked\n\n"
            f"**Request ID:** `{req_id}` &bull; **Session ID:** `{session.session_id}` &bull; **Scenario:** `{scenario}`\n\n"
            f"> **Reason:** {reason}\n"
            f"> **Detected Pattern:** `{pattern}`"
            f"{extra_detail}\n\n"
            f"Execution was halted at the security perimeter. No backend actions or agent tools were executed."
        )

        session.add_message(role="assistant", content=blocked_response, request_id=req_id)
        session.add_security_event({
            "request_id": req_id,
            "session_id": session.session_id,
            "conversation_id": session_ctx.conversation_id,
            "timestamp": datetime.now().isoformat(),
            "scenario": scenario,
            "reason": reason,
            "pattern": pattern
        })

        elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        return ChatResponse(
            request_id=req_id,
            session_id=session.session_id,
            status="blocked",
            response=blocked_response,
            scenario=scenario,
            decision="BLOCK",
            user_id=user_id,
            execution_time_ms=elapsed_ms
        )

    # Step 4: Dispatch execution
    try:
        if is_greeting(request.message):
            greeting_text = (
                f"Hello **{session.customer_context.full_name}**! 👋\n\n"
                f"I am the **VulNet FinTech AI Agent**, your simulated banking assistant.\n\n"
                f"- 👤 **Customer ID:** `{session.customer_context.customer_id}`\n"
                f"- 🏦 **Primary Account:** `{session.customer_context.account_id}`\n"
                f"- 💵 **Balance:** `${session.customer_context.balance:,.2f} {session.customer_context.currency}`\n\n"
                "How can I assist your banking queries today?"
            )
            session.add_message(role="assistant", content=greeting_text, request_id=req_id)
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            return ChatResponse(
                request_id=req_id,
                session_id=session.session_id,
                status="completed",
                response=greeting_text,
                decision="ALLOW",
                user_id=user_id,
                execution_time_ms=elapsed_ms
            )

        elif is_balance_query(request.message):
            balance_text = execute_balance_query(
                request.message, user_id, default_acct, req_id, user_role=auth_session.role
            )
            session.add_message(role="assistant", content=balance_text, request_id=req_id)
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            return ChatResponse(
                request_id=req_id,
                session_id=session.session_id,
                status="completed",
                response=balance_text,
                decision="ALLOW",
                user_id=user_id,
                execution_time_ms=elapsed_ms
            )

        elif is_transaction_query(request.message):
            txn_text = execute_transaction_query(
                request.message, user_id, default_acct, req_id, user_role=auth_session.role
            )
            session.add_message(role="assistant", content=txn_text, request_id=req_id)
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            return ChatResponse(
                request_id=req_id,
                session_id=session.session_id,
                status="completed",
                response=txn_text,
                decision="ALLOW",
                user_id=user_id,
                execution_time_ms=elapsed_ms
            )

        else:
            result = orchestrator.process(request.message, session_context=session_ctx)
            pipeline_status = result.get("pipeline_status", "completed")

            main_res = result.get("main_agent") or {}
            drift = main_res.get("goal_drift_detected", False)
            active_goal = main_res.get("active_goal", "")

            if mode == "vulnerable" and drift:
                outcome = (
                    f"### ⚠️ Vulnerable Mode Simulation (ASI01)\n\n"
                    f"**Request ID:** `{req_id}`\n\n"
                    f"Goal Drift Detected: The agent adopted hijacked goal `{active_goal}`.\n\n"
                    f"Result: {result.get('final_response', 'Executed simulated action under hijacked goal.')}"
                )
            else:
                outcome = (
                    f"### 🤖 Multi-Agent FinTech Analysis\n\n"
                    f"**Request ID:** `{req_id}`\n\n"
                    f"{result.get('final_response', 'The multi-agent pipeline processed your request safely.')}"
                )

            session.add_message(role="assistant", content=outcome, request_id=req_id)
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            return ChatResponse(
                request_id=req_id,
                session_id=session.session_id,
                status=pipeline_status,
                response=outcome,
                scenario=result.get("scenario"),
                decision="ALLOW",
                user_id=user_id,
                execution_time_ms=elapsed_ms
            )

    except Exception as exc:
        logger.error("Internal processing error in /chat: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the chat request."
        )
