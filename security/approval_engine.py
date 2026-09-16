"""
VulNet FinTech AI Agent Security Lab - Human-in-the-Loop Approval Engine
Level 2 Step 14: Human-in-the-Loop Approval

Provides centralized approval management for high-risk simulated financial actions.

CRITICAL SECURITY INVARIANTS:
1. An AI agent must NEVER approve its own high-risk transactions or actions.
2. High-risk operations (e.g., fund transfers >= threshold, policy changes, card freezes)
   mandate explicit human authorization.
3. Approvals carry an expiration window (TTL); expired requests cannot be approved.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from security.security_controller import SecurityController
from auth.roles import Role, normalize_role


class ApprovalDecision:
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


@dataclass
class ApprovalRecord:
    """
    Audit record for human-in-the-loop authorization request.
    """
    approval_id: str
    request_id: str
    user_id: str
    action: str
    risk: str
    decision: str
    timestamp: str
    expires_at: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    approver_id: Optional[str] = None
    approver_role: Optional[str] = None
    decided_at: Optional[str] = None
    rejection_reason: Optional[str] = None
    is_ai_request: bool = True

    def is_expired(self) -> bool:
        """Check whether the approval request has exceeded its TTL."""
        try:
            exp_time = datetime.fromisoformat(self.expires_at)
            # Handle tz-aware vs naive
            now = datetime.now(timezone.utc) if exp_time.tzinfo else datetime.now()
            return now > exp_time
        except Exception:
            return False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ApprovalEngine:
    """
    Manages the lifecycle of human approval requests for high-risk operations.
    """

    # Roles authorized to approve administrative/operational requests
    ADMIN_APPROVER_ROLES = {"ADMIN", "ADMINISTRATOR"}
    OPS_APPROVER_ROLES = {"ADMIN", "ADMINISTRATOR", "SUPPORT_AGENT", "FRAUD_ANALYST"}

    # Prohibited AI identities/roles
    PROHIBITED_AI_ROLES = {
        "AI", "AI_AGENT", "AGENT", "ORCHESTRATOR", "LLM",
        "MAIN_AGENT", "TRANSACTION_AGENT", "CUSTOMER_AGENT",
        "FRAUD_AGENT", "SUPPORT_AGENT_AI", "COMPLIANCE_AGENT"
    }

    def __init__(self, security_controller: Optional[SecurityController] = None):
        self.security_controller = security_controller or SecurityController(mode="secure")
        self._approvals: Dict[str, ApprovalRecord] = {}

    def create_request(
        self,
        user_id: str,
        action: str,
        risk: str = "HIGH",
        request_id: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        ttl_seconds: int = 900,
        is_ai_request: bool = True
    ) -> ApprovalRecord:
        """
        Create a new PENDING approval record for human review.
        """
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=ttl_seconds)
        appr_id = f"APPR-{now.strftime('%Y%m%d%H%M%S')}-{len(self._approvals) + 1:03d}"
        req_id = request_id or f"REQ-{now.strftime('%Y%m%d%H%M%S')}"

        record = ApprovalRecord(
            approval_id=appr_id,
            request_id=req_id,
            user_id=user_id,
            action=action,
            risk=risk.upper(),
            decision=ApprovalDecision.PENDING,
            timestamp=now.isoformat(),
            expires_at=expires.isoformat(),
            parameters=parameters or {},
            is_ai_request=is_ai_request
        )

        self._approvals[appr_id] = record

        # Log security telemetry
        self.security_controller.log_event(
            event_type="HUMAN_APPROVAL_REQUESTED",
            message=f"Human approval requested for action '{action}' (Risk: {risk.upper()}) by user '{user_id}'.",
            severity="WARNING" if risk.upper() in ("HIGH", "CRITICAL") else "INFO",
            component="HITL_APPROVAL",
            decision="PENDING",
            metadata={
                "approval_id": appr_id,
                "action": action,
                "risk": risk.upper(),
                "user_id": user_id
            }
        )

        return record

    def get_request(self, approval_id: str) -> Optional[ApprovalRecord]:
        """Retrieve an approval record by ID and evaluate expiration."""
        record = self._approvals.get(approval_id)
        if record and record.decision == ApprovalDecision.PENDING and record.is_expired():
            record.decision = ApprovalDecision.EXPIRED
        return record

    def list_pending(self) -> List[ApprovalRecord]:
        """Return all active, non-expired pending approval requests."""
        pending = []
        for record in self._approvals.values():
            if record.decision == ApprovalDecision.PENDING:
                if record.is_expired():
                    record.decision = ApprovalDecision.EXPIRED
                else:
                    pending.append(record)
        return pending

    def list_all(self) -> List[ApprovalRecord]:
        """Return all approval records."""
        # Refresh expired statuses
        for record in self._approvals.values():
            if record.decision == ApprovalDecision.PENDING and record.is_expired():
                record.decision = ApprovalDecision.EXPIRED
        return list(self._approvals.values())

    def approve(
        self,
        approval_id: str,
        approver_id: str,
        approver_role: str,
        is_ai_caller: bool = False
    ) -> Dict[str, Any]:
        """
        Approve a pending high-risk action.

        Strictly enforces:
        1. AI agents cannot approve their own or any transactions.
        2. Approvals cannot be granted after TTL expiration.
        3. Approver must hold an authorized human persona role.
        """
        record = self._approvals.get(approval_id)
        if not record:
            return {"status": "error", "reason": f"Approval request '{approval_id}' not found."}

        # -------------------------------------------------------------------
        # 1. ANTI-SELF-APPROVAL INVARIANT: Prohibit AI Agent Approval
        # -------------------------------------------------------------------
        clean_role = str(approver_role).strip().upper()
        clean_approver = str(approver_id).strip().upper()

        if (
            is_ai_caller
            or clean_approver in ("AI_AGENT", "AGENT", "ORCHESTRATOR", "LLM")
            or clean_role in self.PROHIBITED_AI_ROLES
        ):
            self.security_controller.log_event(
                event_type="AI_SELF_APPROVAL_ATTEMPT_BLOCKED",
                message=f"Adversarial Violation: AI agent '{approver_id}' attempted to approve high-risk action '{record.action}'.",
                severity="CRITICAL",
                scenario="ASI02 - Tool Misuse and Exploitation",
                component="HITL_APPROVAL",
                decision="BLOCK",
                metadata={"approval_id": approval_id, "approver_id": approver_id, "approver_role": approver_role}
            )
            return {
                "status": "blocked",
                "reason": "Security Violation: AI agents are strictly prohibited from approving high-risk actions. Human approval required."
            }

        # -------------------------------------------------------------------
        # 2. Expiration Check
        # -------------------------------------------------------------------
        if record.is_expired():
            record.decision = ApprovalDecision.EXPIRED
            self.security_controller.log_event(
                event_type="HUMAN_APPROVAL_EXPIRED",
                message=f"Approval request '{approval_id}' expired before decision.",
                severity="WARNING",
                component="HITL_APPROVAL",
                decision="BLOCK",
                metadata={"approval_id": approval_id}
            )
            return {
                "status": "blocked",
                "reason": f"Approval request '{approval_id}' has expired and can no longer be approved."
            }

        # -------------------------------------------------------------------
        # 3. Already Decided Check
        # -------------------------------------------------------------------
        if record.decision != ApprovalDecision.PENDING:
            return {
                "status": "error",
                "reason": f"Approval request '{approval_id}' is already {record.decision}."
            }

        # -------------------------------------------------------------------
        # 4. Role Authorization Check
        # -------------------------------------------------------------------
        # Customer can approve self-originated retail operations (e.g. transfer from own account)
        # Admin / Ops can approve any request
        is_self_customer = (
            clean_role == "CUSTOMER"
            and approver_id == record.user_id
            and record.action in ("create_payment", "freeze_card", "unfreeze_card")
        )
        is_admin_or_ops = clean_role in self.OPS_APPROVER_ROLES

        if not (is_self_customer or is_admin_or_ops):
            self.security_controller.log_event(
                event_type="UNAUTHORIZED_APPROVAL_ATTEMPT",
                message=f"Unauthorized role '{approver_role}' attempted to approve '{record.action}'.",
                severity="BLOCKED",
                component="HITL_APPROVAL",
                decision="BLOCK",
                metadata={"approver_id": approver_id, "approver_role": approver_role, "approval_id": approval_id}
            )
            return {
                "status": "blocked",
                "reason": f"Unauthorized: Role '{approver_role}' is not authorized to grant approval for this operation."
            }

        # -------------------------------------------------------------------
        # 5. Grant Approval
        # -------------------------------------------------------------------
        now_str = datetime.now(timezone.utc).isoformat()
        record.decision = ApprovalDecision.APPROVED
        record.approver_id = approver_id
        record.approver_role = clean_role
        record.decided_at = now_str

        self.security_controller.log_event(
            event_type="HUMAN_APPROVAL_GRANTED",
            message=f"Approval '{approval_id}' GRANTED for action '{record.action}' by human '{approver_id}' ({clean_role}).",
            severity="INFO",
            component="HITL_APPROVAL",
            decision="ALLOW",
            metadata={
                "approval_id": approval_id,
                "approver_id": approver_id,
                "approver_role": clean_role,
                "action": record.action
            }
        )

        return {
            "status": "success",
            "decision": ApprovalDecision.APPROVED,
            "approval_id": approval_id,
            "record": record.to_dict()
        }

    def reject(
        self,
        approval_id: str,
        approver_id: str,
        approver_role: str,
        reason: str = "Rejected by human reviewer",
        is_ai_caller: bool = False
    ) -> Dict[str, Any]:
        """
        Reject a pending high-risk action.
        """
        record = self._approvals.get(approval_id)
        if not record:
            return {"status": "error", "reason": f"Approval request '{approval_id}' not found."}

        clean_role = str(approver_role).strip().upper()
        if is_ai_caller or clean_role in self.PROHIBITED_AI_ROLES:
            return {
                "status": "blocked",
                "reason": "Security Violation: AI agents cannot issue approval or rejection decisions."
            }

        if record.decision != ApprovalDecision.PENDING:
            return {
                "status": "error",
                "reason": f"Approval request '{approval_id}' is already {record.decision}."
            }

        now_str = datetime.now(timezone.utc).isoformat()
        record.decision = ApprovalDecision.REJECTED
        record.approver_id = approver_id
        record.approver_role = clean_role
        record.decided_at = now_str
        record.rejection_reason = reason

        self.security_controller.log_event(
            event_type="HUMAN_APPROVAL_REJECTED",
            message=f"Approval '{approval_id}' REJECTED for action '{record.action}' by reviewer '{approver_id}': {reason}",
            severity="WARNING",
            component="HITL_APPROVAL",
            decision="BLOCK",
            metadata={
                "approval_id": approval_id,
                "approver_id": approver_id,
                "reason": reason
            }
        )

        return {
            "status": "success",
            "decision": ApprovalDecision.REJECTED,
            "approval_id": approval_id,
            "record": record.to_dict()
        }


# Singleton instance accessor
_SHARED_APPROVAL_ENGINE: Optional[ApprovalEngine] = None


def get_approval_engine() -> ApprovalEngine:
    """Return singleton shared ApprovalEngine instance."""
    global _SHARED_APPROVAL_ENGINE
    if _SHARED_APPROVAL_ENGINE is None:
        _SHARED_APPROVAL_ENGINE = ApprovalEngine()
    return _SHARED_APPROVAL_ENGINE
