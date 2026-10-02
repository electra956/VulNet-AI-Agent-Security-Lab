"""
Human approval queue API. The approver is the *authenticated session's* user and role; the request body can never
name a different approver. AI/agent identities cannot approve (enforced by the approval engine and by RBAC here).
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from auth.authentication import get_auth_service
from auth.models import UnauthorizedError
from auth.roles import normalize_role
from fintech.transaction_lifecycle import get_transaction_lifecycle_service
from security.approval_engine import ApprovalEngine, get_approval_engine

router = APIRouter(prefix="/approvals", tags=["Approvals"])
HTTP_403 = status.HTTP_403_FORBIDDEN


class DecisionRequest(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=128)
    reason: Optional[str] = Field(None, max_length=300)


def _session(session_id: str):
    try:
        return get_auth_service().authenticate_request(session_id)
    except UnauthorizedError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Authentication required: {exc}")


def _view(rec) -> Dict[str, Any]:
    d = rec.to_dict()
    return {k: d[k] for k in ("approval_id", "request_id", "user_id", "action", "risk", "decision", "timestamp", "expires_at",
                              "parameters", "approver_id", "approver_role", "decided_at", "rejection_reason")}


@router.get("")
def list_approvals(session_id: str) -> Dict[str, Any]:
    sess = _session(session_id)
    can_decide = normalize_role(sess.role).value in ApprovalEngine.OPS_APPROVER_ROLES
    recs = [r for r in get_approval_engine().list_all() if can_decide or r.user_id == sess.user_id]
    return {"can_decide": can_decide, "approvals": [_view(r) for r in recs]}


def _decide(approval_id: str, body: DecisionRequest, approve: bool) -> Dict[str, Any]:
    sess = _session(body.session_id)
    role = normalize_role(sess.role).value
    if role not in ApprovalEngine.OPS_APPROVER_ROLES:
        raise HTTPException(status_code=HTTP_403, detail=f"Role {role} may not decide approvals.")
    rec = get_approval_engine().get_request(approval_id)
    if rec is not None and rec.user_id == sess.user_id:
        raise HTTPException(status_code=HTTP_403, detail="You cannot decide your own request.")
    life = get_transaction_lifecycle_service()
    out = (life.complete_approved(approval_id, sess.user_id, role) if approve
           else life.reject_pending(approval_id, sess.user_id, role, body.reason or "Rejected via API"))
    if out.get("status") == "error" and "not found" in str(out.get("reason", "")).lower():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=out["reason"])
    return out


@router.post("/{approval_id}/approve")
def approve(approval_id: str, body: DecisionRequest) -> Dict[str, Any]:
    return _decide(approval_id, body, True)


@router.post("/{approval_id}/reject")
def reject(approval_id: str, body: DecisionRequest) -> Dict[str, Any]:
    return _decide(approval_id, body, False)
