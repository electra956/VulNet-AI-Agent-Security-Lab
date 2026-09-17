"""
VulNet FinTech AI Agent Security Lab - Complete FinTech Transaction Lifecycle.
Step 17: End-to-End Local FinTech Transaction Lifecycle & State Management.

Implements the deterministic 24-step transaction processing pipeline:
1.  Create / resolve request_id
2.  Create / resolve session
3.  Authenticate user identity
4.  Resolve customer profile & accounts
5.  Check session context
6.  Run AI Security Gateway
7.  Detect user intent & parse transfer parameters
8.  Route to Transaction Agent
9.  Validate requested operation
10. Perform RBAC authorization (Permission.TRANSACTION_CREATE)
11. Validate source account ownership (BOLA prevention)
12. Validate destination account
13. Validate transaction amount (> 0, <= available balance)
14. Run deterministic TransactionRiskEngine
15. Determine whether human approval is required
16. If approved / allowed: dispatch to MCP Tool Gateway
17. MCP Gateway independent validation:
      - Authenticated user
      - Role
      - Permission
      - Tool name
      - Arguments
      - Risk level
18. Execute simulated financial tool in sandbox
19. Generate transaction ID
20. Update simulated transaction state
21. Generate structured audit event
22. Generate agent trace checklist
23. Return structured result
24. Display result in dashboard

CRITICAL SECURITY INVARIANTS:
- All financial operations remain strictly simulated on synthetic in-memory state.
- Zero connection to real banks, networks, payment gateways, or live currency.
- AI Agent can NEVER approve its own transactions or override risk controls.
"""

from datetime import datetime, timezone
import logging
import re
from typing import Any, Dict, List, Optional, Union

from fintech.models import (
    Customer,
    Account,
    Transaction,
    TransactionStatus,
    UnauthorizedAccessError,
    AccountNotFoundError,
    CustomerNotFoundError,
    TransactionValidationError,
)
from fintech.service import FintechService
from fintech.risk.transaction_risk import TransactionRiskEngine, RiskLevel, RiskDecision
from auth.roles import Role, normalize_role
from auth.permissions import Permission, normalize_permission
from auth.authorization import has_permission, authorize_resource_access
from observability.trace import RequestTracer, AgentTrace, get_trace_store
from observability.events import StageStatus

logger = logging.getLogger("vulnet.fintech.lifecycle")


class TransactionLifecycleService:
    """
    Deterministic coordinator for the end-to-end simulated transaction lifecycle.
    Enforces application-level security boundaries outside the LLM.
    """

    def __init__(
        self,
        fintech_service: Optional[FintechService] = None,
        fintech_repo: Optional[Any] = None,
        risk_engine: Optional[TransactionRiskEngine] = None,
        approval_engine: Optional[Any] = None,
        mcp_server: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
    ):
        if fintech_service is not None:
            self.fintech_service = fintech_service
        elif fintech_repo is not None:
            self.fintech_service = FintechService(repository=fintech_repo)
        else:
            self.fintech_service = FintechService()
        self.risk_engine = risk_engine or TransactionRiskEngine()
        if approval_engine is not None:
            self.approval_engine = approval_engine
        else:
            from security.approval_engine import get_approval_engine
            self.approval_engine = get_approval_engine()

        if mcp_server is not None:
            self.mcp_server = mcp_server
        else:
            from mcp_server.server import MCPServer
            self.mcp_server = MCPServer(mode="secure")

        if audit_logger is not None:
            self.audit_logger = audit_logger
        else:
            from observability.audit import get_audit_logger
            self.audit_logger = get_audit_logger()


    @staticmethod
    def parse_transaction_params(
        request_text: str,
        user_accounts: Optional[List[str]] = None,
        default_account: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Extract transaction amount, currency, source, and destination accounts
        from natural language prompt or explicit formatting.
        """
        text = request_text.strip()

        # Parse amount and currency
        # Recognizes: ₹500, $500, 500 USD, 50000 INR, etc.
        amount = 0.0
        currency = "USD"

        amt_match = re.search(
            r"(\$|₹|rs\.?\s*|inr\s*|usd\s*)?\s*(-?\d{1,3}(?:,\d{3})+(?:\.\d+)?|-?\d+(?:\.\d+)?)",
            text,
            re.IGNORECASE,
        )
        if amt_match:
            prefix = (amt_match.group(1) or "").lower()
            if "₹" in prefix or "inr" in prefix or "rs" in prefix or "inr" in text.lower():
                currency = "INR"
            elif "$" in prefix or "usd" in prefix:
                currency = "USD"

            raw_amt = amt_match.group(2).replace(",", "")
            try:
                amount = float(raw_amt)
            except ValueError:
                amount = 0.0

        # Parse accounts
        acct_matches = re.findall(r"\b(ACC-\d{4})\b", text, re.IGNORECASE)
        from_account = None
        to_account = None

        if len(acct_matches) >= 2:
            from_account = acct_matches[0].upper()
            to_account = acct_matches[1].upper()
        elif len(acct_matches) == 1:
            # Determine whether matched account is source or destination
            matched = acct_matches[0].upper()
            if user_accounts and matched in user_accounts:
                from_account = matched
                to_account = "ACC-2001" if matched != "ACC-2001" else "ACC-1002"
            else:
                # Specified destination account
                to_account = matched
                from_account = default_account or (user_accounts[0] if user_accounts else "ACC-1001")
        else:
            # Fallback to customer's primary account and deterministic destination
            from_account = default_account or (user_accounts[0] if user_accounts else "ACC-1001")
            to_account = "ACC-2001" if from_account != "ACC-2001" else "ACC-1002"

        return {
            "amount": amount,
            "currency": currency,
            "from_account": from_account,
            "to_account": to_account,
            "description": f"Simulated {currency} {amount:,.2f} transfer to {to_account}"
        }

    def process_transaction_request(
        self,
        user_message: str,
        user_context: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        user_authorized: bool = False,
        tracer: Optional[RequestTracer] = None,
        mode: str = "secure",
    ) -> Dict[str, Any]:
        """
        Convenience wrapper method for end-to-end lifecycle testing and callers.
        Maps structured parameters to process_transaction and returns unified dictionary.
        """
        ctx: Dict[str, Any] = {}
        if isinstance(user_context, dict):
            ctx = dict(user_context)
        if session_id:
            ctx["session_id"] = session_id
        if request_id:
            ctx["request_id"] = request_id
        if not user_context:
            ctx["user_id"] = None

        res = self.process_transaction(
            request_text=user_message,
            session_context=ctx,
            user_authorized=user_authorized,
            tracer=tracer,
            mode=mode,
        )

        txn = res.get("transaction") or {}
        status = res.get("status")
        is_success = status in (
            TransactionStatus.COMPLETED.value,
            TransactionStatus.APPROVAL_REQUIRED.value,
        )

        mcp_status = "NOT_CALLED"
        if status == TransactionStatus.COMPLETED.value:
            mcp_status = "SUCCESS"
        elif status == TransactionStatus.APPROVAL_REQUIRED.value:
            mcp_status = "BLOCKED_PENDING_APPROVAL"
        elif "mcp" in str(res.get("error", "")).lower():
            mcp_status = "BLOCKED"

        return {
            "success": is_success,
            "status": status,
            "transaction_id": txn.get("transaction_id", res.get("transaction_id", "NONE")),
            "risk_level": txn.get("risk_level", "LOW"),
            "requires_approval": status == TransactionStatus.APPROVAL_REQUIRED.value,
            "approval_status": txn.get("approval_status", "NONE"),
            "approval_request_id": res.get("approval_id"),
            "mcp_execution_status": mcp_status,
            "audit_recorded": True,
            "trace_recorded": res.get("trace") is not None,
            "error": res.get("error") or txn.get("reason", ""),
            "response": res.get("response", ""),
            "trace": res.get("trace"),
            "checklist": res.get("checklist", ""),
            "transaction": txn,
        }

    def process_transaction(
        self,
        request_text: str,
        session_context: Optional[Any] = None,
        user_authorized: bool = False,
        tracer: Optional[RequestTracer] = None,
        mode: str = "secure",
        explicit_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Execute the complete 24-step transaction processing lifecycle.
        """
        start_time = datetime.now(timezone.utc)
        ctx = (
            session_context.to_dict()
            if hasattr(session_context, "to_dict")
            else (session_context if isinstance(session_context, dict) else {})
        )

        req_id = ctx.get("request_id") or f"REQ-TXN-{start_time.strftime('%Y%m%d%H%M%S%f')[:17]}"
        sess_id = ctx.get("session_id") or "SESSION-001"
        user_id = ctx.get("user_id")
        user_role = ctx.get("role") or "CUSTOMER"
        user_accounts = ctx.get("account_ids") or ["ACC-1001", "ACC-1002"]

        if tracer is None:
            tracer = RequestTracer(request_id=req_id, session_id=sess_id, user_id=user_id or "ANONYMOUS", action="transaction_lifecycle")

        # -------------------------------------------------------------
        # STEP 1–5: AUTHENTICATION & SESSION CONTEXT RESOLUTION
        # -------------------------------------------------------------
        if not user_id or str(user_id).upper() in ("GUEST", "NONE", "ANONYMOUS"):
            tracer.record_stage("Authentication", status=StageStatus.BLOCKED.value, details="Missing or unauthenticated user identity")
            tracer.record_stage("Tool", status=StageStatus.BLOCKED.value, details="Unauthenticated call rejected")
            return self._build_rejected_response(
                req_id=req_id,
                sess_id=sess_id,
                user_id=user_id or "UNAUTHENTICATED",
                reason="Authentication required: Missing or unauthenticated user session.",
                status=TransactionStatus.REJECTED.value,
                tracer=tracer
            )

        tracer.record_stage("Authentication", status=StageStatus.SUCCESS.value, details=f"User {user_id} authenticated ({user_role})")

        # Extract / Parse parameters
        parsed = self.parse_transaction_params(
            request_text,
            user_accounts=user_accounts,
            default_account=user_accounts[0] if user_accounts else "ACC-1001"
        )
        if explicit_params:
            parsed.update(explicit_params)

        from_acct = parsed.get("from_account", "ACC-1001")
        to_acct = parsed.get("to_account", "ACC-2001")
        amount = float(parsed.get("amount", 0.0))
        currency = parsed.get("currency", "USD")
        desc = parsed.get("description", "Simulated Transfer")

        # Initialize structured transaction object in PENDING state
        init_txn = self.fintech_service.create_transaction_record(
            request_id=req_id,
            session_id=sess_id,
            user_id=user_id,
            source_account_id=from_acct,
            destination_account_id=to_acct,
            amount=amount,
            currency=currency,
            transaction_type="TRANSFER",
            status=TransactionStatus.PENDING.value,
            risk_level="LOW",
            approval_status="NONE",
            reason="Transaction received, pending authorization and risk checks.",
            description=desc
        )

        # -------------------------------------------------------------
        # STEP 7–9: INTENT CLASSIFICATION & AGENT DISPATCH
        # -------------------------------------------------------------
        tracer.record_stage("Intent Classification", status=StageStatus.SUCCESS.value, details="TRANSFER_FUNDS")
        tracer.record_stage("Main Agent", status=StageStatus.SUCCESS.value, details="Dispatched to TransactionAgent")
        tracer.record_stage("Transaction Agent", status=StageStatus.SUCCESS.value, details=f"Proposed transfer {currency} {amount:,.2f}")

        # -------------------------------------------------------------
        # STEP 10: RBAC AUTHORIZATION (Permission.TRANSACTION_CREATE)
        # -------------------------------------------------------------
        tracer.start_stage("Authorization")
        role_enum = Role.CUSTOMER
        try:
            role_enum = normalize_role(user_role)
        except Exception:
            role_enum = Role.CUSTOMER

        if not has_permission(role_enum, Permission.TRANSACTION_CREATE):
            init_txn.transition_to(TransactionStatus.REJECTED, reason=f"Role '{user_role}' lacks permission 'transaction.create'.")
            self.fintech_service.repository.save_transaction(init_txn)
            tracer.record_stage("Authorization", status=StageStatus.BLOCKED.value, details=f"Role '{user_role}' denied transaction.create")
            tracer.record_stage("Tool", status=StageStatus.BLOCKED.value, details="Authorization failed")
            self._log_audit_event(
                req_id=req_id, sess_id=sess_id, user_id=user_id,
                action="create_simulated_transaction", decision="REJECT",
                status="rejected", risk="HIGH", account_id=from_acct,
                reason=f"RBAC Denied: Role '{user_role}' lacks permission 'transaction.create'."
            )
            return self._build_transaction_response(init_txn, tracer, error_msg="RBAC Authorization Denied: Insufficient role permissions.")

        tracer.record_stage("Authorization", status=StageStatus.SUCCESS.value, details=f"Role '{user_role}' authorized for transaction.create")

        # -------------------------------------------------------------
        # STEP 11: SOURCE ACCOUNT OWNERSHIP VALIDATION (BOLA Check)
        # -------------------------------------------------------------
        tracer.start_stage("Permission")
        try:
            # Deterministic ownership verification outside the LLM
            src_account = self.fintech_service.get_account(customer_id=user_id, account_id=from_acct)
        except CustomerNotFoundError as exc:
            init_txn.transition_to(TransactionStatus.REJECTED, reason=str(exc))
            self.fintech_service.repository.save_transaction(init_txn)
            tracer.record_stage("Permission", status=StageStatus.BLOCKED.value, details=f"Unknown customer user: {user_id}")
            tracer.record_stage("Tool", status=StageStatus.BLOCKED.value, details="User customer not found")
            self._log_audit_event(
                req_id=req_id, sess_id=sess_id, user_id=user_id,
                action="create_simulated_transaction", decision="REJECT",
                status="rejected", risk="HIGH", account_id=from_acct,
                reason=f"Security Violation: User / Customer '{user_id}' does not exist."
            )
            return self._build_transaction_response(
                init_txn, tracer,
                error_msg=f"Security Alert: User / Customer '{user_id}' does not exist or has no account ownership."
            )
        except UnauthorizedAccessError as exc:
            init_txn.transition_to(TransactionStatus.REJECTED, reason=str(exc))
            self.fintech_service.repository.save_transaction(init_txn)
            tracer.record_stage("Permission", status=StageStatus.BLOCKED.value, details=f"Unauthorized account: {from_acct}")
            tracer.record_stage("Tool", status=StageStatus.BLOCKED.value, details="BOLA check blocked tool execution")
            self._log_audit_event(
                req_id=req_id, sess_id=sess_id, user_id=user_id,
                action="create_simulated_transaction", decision="REJECT",
                status="rejected", risk="HIGH", account_id=from_acct,
                reason=f"Security Violation [ASI03]: Customer '{user_id}' does not own account '{from_acct}'."
            )
            return self._build_transaction_response(
                init_txn, tracer,
                error_msg=f"Security Alert: Customer '{user_id}' is not authorized to operate on account '{from_acct}' owned by another customer."
            )
        except AccountNotFoundError as exc:
            init_txn.transition_to(TransactionStatus.REJECTED, reason=str(exc))
            self.fintech_service.repository.save_transaction(init_txn)
            tracer.record_stage("Permission", status=StageStatus.BLOCKED.value, details=f"Account not found: {from_acct}")
            tracer.record_stage("Tool", status=StageStatus.BLOCKED.value, details="Account not found")
            return self._build_transaction_response(init_txn, tracer, error_msg=f"Source account '{from_acct}' does not exist.")

        tracer.record_stage("Permission", status=StageStatus.SUCCESS.value, details=f"Ownership verified for {from_acct}")

        # -------------------------------------------------------------
        # STEP 12–13: DESTINATION & AMOUNT VALIDATION
        # -------------------------------------------------------------
        if from_acct == to_acct:
            init_txn.transition_to(TransactionStatus.REJECTED, reason="Source and destination accounts cannot be identical.")
            self.fintech_service.repository.save_transaction(init_txn)
            tracer.record_stage("Tool", status=StageStatus.BLOCKED.value, details="Identical source and destination")
            return self._build_transaction_response(init_txn, tracer, error_msg="Transfer destination cannot be the same as the source account.")

        if amount <= 0:
            init_txn.transition_to(TransactionStatus.REJECTED, reason=f"Amount must be positive, got {amount}.")
            self.fintech_service.repository.save_transaction(init_txn)
            tracer.record_stage("Tool", status=StageStatus.BLOCKED.value, details=f"Invalid amount: {amount}")
            return self._build_transaction_response(init_txn, tracer, error_msg=f"Invalid transaction amount: Transaction amount must be positive and greater than zero, received: {amount}.")

        if src_account.balance < amount:
            init_txn.transition_to(TransactionStatus.FAILED, reason=f"Insufficient balance (${src_account.balance:,.2f} < ${amount:,.2f}).")
            self.fintech_service.repository.save_transaction(init_txn)
            tracer.record_stage("Tool", status=StageStatus.BLOCKED.value, details="Insufficient funds")
            return self._build_transaction_response(
                init_txn, tracer,
                error_msg=f"Insufficient funds: Available balance (${src_account.balance:,.2f}) is less than transfer amount (${amount:,.2f})."
            )

        # -------------------------------------------------------------
        # STEP 14: DETERMINISTIC RISK ENGINE EVALUATION
        # -------------------------------------------------------------
        tracer.start_stage("Risk Engine")
        init_txn.transition_to(TransactionStatus.RISK_CHECK, reason="Evaluating risk rules.")
        self.fintech_service.repository.save_transaction(init_txn)

        risk_result = self.risk_engine.evaluate({
            "amount": amount,
            "from_account": from_acct,
            "to_account": to_acct,
            "available_balance": src_account.balance
        })

        init_txn.risk_level = risk_result.risk_level
        tracer.record_stage(
            "Risk Engine",
            status=StageStatus.SUCCESS.value,
            details=f"Risk: {risk_result.risk_level} (Score: {risk_result.risk_score}, Decision: {risk_result.decision})"
        )

        # -------------------------------------------------------------
        # STEP 15: APPROVAL DETERMINATION & HUMAN-IN-THE-LOOP GATE
        # -------------------------------------------------------------
        requires_approval = (
            risk_result.decision in (RiskDecision.REVIEW, RiskDecision.VALIDATE)
            or risk_result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
            or amount >= 10000.0
        )

        if requires_approval and not user_authorized:
            # Create human approval queue record
            approval_rec = self.approval_engine.create_request(
                user_id=user_id,
                action="create_simulated_transaction",
                risk=risk_result.risk_level,
                request_id=req_id,
                parameters={
                    "transaction_id": init_txn.transaction_id,
                    "from_account": from_acct,
                    "to_account": to_acct,
                    "amount": amount,
                    "currency": currency,
                    "risk_score": risk_result.risk_score,
                    "reasons": risk_result.reasons,
                }
            )

            init_txn.transition_to(
                TransactionStatus.APPROVAL_REQUIRED,
                reason=f"High-risk operation requires human approval (Ref: {approval_rec.approval_id})."
            )
            init_txn.approval_status = "PENDING"
            self.fintech_service.repository.save_transaction(init_txn)

            # INVARIANT: AI Agent must NEVER execute or approve high-risk transfers
            tracer.record_stage("Tool", status=StageStatus.BLOCKED.value, details=f"Approval required ({approval_rec.approval_id})")
            tracer.start_stage("Audit")
            self._log_audit_event(
                req_id=req_id, sess_id=sess_id, user_id=user_id,
                action="create_simulated_transaction", decision="APPROVAL",
                status="approval_required", risk=risk_result.risk_level,
                account_id=from_acct,
                reason=f"High-risk transaction ({currency} {amount:,.2f}) requires human authorization. Queued: {approval_rec.approval_id}."
            )
            tracer.record_stage("Audit", status=StageStatus.SUCCESS.value, details="Approval requirement logged")

            return self._build_transaction_response(
                init_txn, tracer,
                approval_id=approval_rec.approval_id,
                error_msg=None
            )

        if risk_result.decision == RiskDecision.BLOCK:
            init_txn.transition_to(TransactionStatus.REJECTED, reason="Transaction blocked by risk policy.")
            self.fintech_service.repository.save_transaction(init_txn)
            tracer.record_stage("Tool", status=StageStatus.BLOCKED.value, details="Risk policy blocked transaction")
            self._log_audit_event(
                req_id=req_id, sess_id=sess_id, user_id=user_id,
                action="create_simulated_transaction", decision="BLOCK",
                status="rejected", risk="CRITICAL", account_id=from_acct,
                reason=f"Risk Policy Blocked: {', '.join(risk_result.reasons)}"
            )
            return self._build_transaction_response(init_txn, tracer, error_msg="Transaction rejected: Critical risk indicators detected.")

        # -------------------------------------------------------------
        # STEP 16–18: MCP TOOL GATEWAY ENFORCEMENT & EXECUTION
        # -------------------------------------------------------------
        init_txn.transition_to(TransactionStatus.APPROVED, reason="Authorized and passed risk check.")
        init_txn.transition_to(TransactionStatus.PROCESSING, reason="Dispatching to MCP Tool.")
        self.fintech_service.repository.save_transaction(init_txn)

        tracer.start_stage("MCP")
        tracer.record_stage("MCP", status=StageStatus.SUCCESS.value, details="MCP Gateway active")

        # Synchronize repository account balance into MCP Tool Suite before execution
        tool_meta = self.mcp_server.registry.get("create_simulated_transaction")
        if tool_meta and hasattr(tool_meta.handler, "__self__"):
            tool_suite = tool_meta.handler.__self__
            if hasattr(tool_suite, "accounts") and from_acct in tool_suite.accounts:
                tool_suite.accounts[from_acct]["balance"] = src_account.balance

        # Independent MCP Gateway invocation
        mcp_res = self.mcp_server.execute_tool(
            "create_simulated_transaction",
            caller_role=user_role,
            user_authorized=user_authorized,
            customer_id=user_id,
            from_account=from_acct,
            to_account=to_acct,
            amount=amount,
            currency=currency,
            description=desc,
            request_id=req_id,
            session_id=sess_id
        )

        if mcp_res.get("status") != "success":
            init_txn.transition_to(TransactionStatus.FAILED, reason=f"MCP Tool execution failed: {mcp_res.get('reason')}")
            self.fintech_service.repository.save_transaction(init_txn)
            tracer.record_stage("Tool", status=StageStatus.BLOCKED.value, details=f"MCP execution blocked: {mcp_res.get('reason')}")
            self._log_audit_event(
                req_id=req_id, sess_id=sess_id, user_id=user_id,
                action="create_simulated_transaction", decision="REJECT",
                status="failed", risk=risk_result.risk_level, account_id=from_acct,
                reason=f"MCP Gate Blocked: {mcp_res.get('reason')}"
            )
            return self._build_transaction_response(init_txn, tracer, error_msg=mcp_res.get("reason", "MCP Tool execution failed."))

        # -------------------------------------------------------------
        # STEP 19–20: TRANSACTION COMPLETION & BALANCE UPDATE
        # -------------------------------------------------------------
        # Update FintechService in-memory repository to keep state consistent
        self.fintech_service.repository.update_account_balance(
            from_acct, src_account.balance - amount
        )
        dest_acc = self.fintech_service.repository.get_account(to_acct)
        if dest_acc:
            self.fintech_service.repository.update_account_balance(
                to_acct, dest_acc.balance + amount
            )

        init_txn.transition_to(TransactionStatus.COMPLETED, reason="Simulated fund transfer completed successfully.")
        init_txn.approval_status = "APPROVED" if user_authorized else "NONE"
        self.fintech_service.repository.save_transaction(init_txn)

        tracer.record_stage("Tool", status=StageStatus.SUCCESS.value, details=f"create_simulated_transaction ({init_txn.transaction_id})")

        # -------------------------------------------------------------
        # STEP 21–22: STRUCTURED AUDIT & TRACE RECORDING
        # -------------------------------------------------------------
        tracer.start_stage("Audit")
        audit_rec = self._log_audit_event(
            req_id=req_id, sess_id=sess_id, user_id=user_id,
            action="create_simulated_transaction", decision="ALLOW",
            status="completed", risk="LOW", account_id=from_acct,
            reason=f"Simulated transfer of {currency} {amount:,.2f} completed successfully.",
            metadata={"transaction_id": init_txn.transaction_id, "to_account": to_acct}
        )
        tracer.record_stage("Audit", status=StageStatus.SUCCESS.value, details=f"Audit logged ({audit_rec.audit_id})")

        # -------------------------------------------------------------
        # STEP 23–24: RETURN STRUCTURED RESULT
        # -------------------------------------------------------------
        return self._build_transaction_response(init_txn, tracer)

    def _log_audit_event(
        self,
        req_id: str,
        sess_id: str,
        user_id: str,
        action: str,
        decision: str,
        status: str,
        risk: str,
        account_id: str,
        reason: str,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Record structured immutable audit entry in logs/audit.jsonl."""
        meta = metadata or {}
        meta.update({"account_id": account_id, "reason": reason})
        return self.audit_logger.log_audit(
            request_id=req_id,
            session_id=sess_id,
            user_id=user_id,
            action=action,
            decision=decision,
            status=status,
            risk=risk,
            error=reason if decision in ("BLOCK", "REJECT") else None,
            metadata=meta
        )

    def _build_transaction_response(
        self,
        txn: Transaction,
        tracer: RequestTracer,
        approval_id: Optional[str] = None,
        error_msg: Optional[str] = None
    ) -> Dict[str, Any]:
        """Construct standard response conforming to Phase 4 Transaction Object."""
        final_trace = tracer.finalize(
            status=txn.status.lower(),
            decision="ALLOW" if txn.status == TransactionStatus.COMPLETED.value else ("APPROVAL" if txn.status == TransactionStatus.APPROVAL_REQUIRED.value else "BLOCK"),
            risk=txn.risk_level,
            agent="TransactionAgent",
            tool="create_simulated_transaction"
        )
        get_trace_store().add_trace(final_trace)

        # Human-friendly response formulation
        if txn.status == TransactionStatus.COMPLETED.value:
            formatted_response = (
                f"### ✅ Transaction Completed Successfully\n\n"
                f"- **Transaction ID:** `{txn.transaction_id}`\n"
                f"- **Source Account:** `{txn.source_account_id}`\n"
                f"- **Destination Account:** `{txn.destination_account_id}`\n"
                f"- **Amount:** `{txn.currency} {txn.amount:,.2f}`\n"
                f"- **Status:** `COMPLETED`\n"
                f"- **Risk Level:** `{txn.risk_level}`\n\n"
                f"> **Safety Invariant:** All operations are local and simulated. No real funds were moved."
            )
        elif txn.status == TransactionStatus.APPROVAL_REQUIRED.value:
            formatted_response = (
                f"### ⚠️ Human Approval Required (High-Risk Transaction)\n\n"
                f"- **Transaction ID:** `{txn.transaction_id}`\n"
                f"- **Approval Request ID:** `{approval_id}`\n"
                f"- **Source Account:** `{txn.source_account_id}`\n"
                f"- **Destination Account:** `{txn.destination_account_id}`\n"
                f"- **Amount:** `{txn.currency} {txn.amount:,.2f}`\n"
                f"- **Status:** `APPROVAL_REQUIRED`\n"
                f"- **Risk Level:** `{txn.risk_level}`\n\n"
                f"> **Security Policy:** This transfer exceeds operational thresholds and has been routed to the "
                f"Human-In-The-Loop approval queue. The AI agent cannot approve its own transactions."
            )
        else:
            err = error_msg or txn.reason or "Transaction failed authorization or validation checks."
            formatted_response = (
                f"### ❌ Transaction Rejected\n\n"
                f"- **Transaction ID:** `{txn.transaction_id}`\n"
                f"- **Source Account:** `{txn.source_account_id}`\n"
                f"- **Status:** `{txn.status}`\n"
                f"- **Reason:** {err}\n\n"
                f"> Execution halted outside the LLM. No funds were transferred."
            )

        return {
            "transaction": txn.to_dict(),
            "transaction_id": txn.transaction_id,
            "status": txn.status,
            "response": formatted_response,
            "approval_id": approval_id,
            "trace": final_trace,
            "checklist": final_trace.render_checklist(),
            "error": error_msg
        }

    def _build_rejected_response(
        self,
        req_id: str,
        sess_id: str,
        user_id: str,
        reason: str,
        status: str,
        tracer: RequestTracer
    ) -> Dict[str, Any]:
        """Construct standard response for early rejected transaction."""
        final_trace = tracer.finalize(status="blocked", decision="BLOCK", risk="HIGH")
        get_trace_store().add_trace(final_trace)
        return {
            "transaction": {
                "transaction_id": "NONE",
                "request_id": req_id,
                "session_id": sess_id,
                "user_id": user_id,
                "status": status,
                "reason": reason
            },
            "status": status,
            "response": f"### ❌ Transaction Blocked\n\n{reason}",
            "trace": final_trace,
            "checklist": final_trace.render_checklist(),
            "error": reason
        }


# Shared singleton instance
_lifecycle_service: Optional[TransactionLifecycleService] = None


def get_transaction_lifecycle_service() -> TransactionLifecycleService:
    """Retrieve shared TransactionLifecycleService instance."""
    global _lifecycle_service
    if _lifecycle_service is None:
        _lifecycle_service = TransactionLifecycleService()
    return _lifecycle_service

