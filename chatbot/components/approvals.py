"""
Human approval queue for high-risk transfers.

The decision is made by the *logged-in human* (their real authenticated user id and role) - never by the agent and
never by a hard-coded approver. Customers can see the status of their own requests but cannot decide them.
"""

from __future__ import annotations

import streamlit as st

from auth.authentication import get_auth_service
from auth.roles import normalize_role
from fintech.service import get_shared_fintech_service
from fintech.transaction_lifecycle import get_transaction_lifecycle_service
from security.approval_engine import ApprovalEngine, get_approval_engine


def _row(rec, svc):
    txn = svc.repository.get_transaction(rec.parameters.get("transaction_id", ""))
    return {"approval": rec.approval_id, "requested by": rec.user_id, "risk": rec.risk, "decision": rec.decision,
            "transaction": rec.parameters.get("transaction_id"), "txn status": txn.status if txn else "n/a",
            "from": rec.parameters.get("from_account"), "to": rec.parameters.get("to_account"),
            "amount": rec.parameters.get("amount"), "decided by": rec.approver_id or "-", "expires": rec.expires_at[:19]}


def render_approvals_view() -> None:
    st.title("✅ Approvals")
    st.caption("High-risk transfers wait here for a human. The AI cannot approve; approval can never override a risk-policy BLOCK.")
    sess = get_auth_service().get_session(st.session_state.get("active_session_id", ""))
    if sess is None:
        st.warning("Sign in to use the approval queue.")
        return
    role = normalize_role(sess.role).value
    can_decide = role in ApprovalEngine.OPS_APPROVER_ROLES
    svc, engine, life = get_shared_fintech_service(), get_approval_engine(), get_transaction_lifecycle_service()
    st.markdown(f"Signed in as **{sess.user_id}** · role **{role}** · " + ("✅ may decide approvals" if can_decide else "👁 read-only"))

    pending = [r for r in engine.list_pending() if can_decide or r.user_id == sess.user_id]
    st.subheader(f"Pending ({len(pending)})")
    if not pending:
        st.info("Nothing waiting. Ask the chat to `Transfer 11000 dollars from ACC-1002 to ACC-2001` to create a request.")
    for rec in pending:
        p = rec.parameters
        acct = svc.repository.get_account(p.get("from_account", ""))
        known = svc.repository.get_account(p.get("to_account", "")) is not None
        with st.expander(f"{rec.approval_id} · {p.get('currency', '')} {p.get('amount', 0):,.2f} {p.get('from_account')} → {p.get('to_account')} · {rec.risk}", expanded=True):
            c1, c2 = st.columns(2)
            c1.markdown("**Evidence (from the ledger and risk engine, not from the agent)**")
            c1.json({"deterministic_risk": rec.risk, "risk_score": p.get("risk_score"), "reasons": p.get("reasons"),
                     "beneficiary_known_account": known, "source_balance": acct.balance if acct else None,
                     "requested_by": rec.user_id, "request_id": rec.request_id})
            c2.markdown("**Consequence**")
            c2.write(f"Approving moves {p.get('currency', '')} {p.get('amount', 0):,.2f} of simulated funds from `{p.get('from_account')}` "
                     f"to `{p.get('to_account')}`. No real money is involved.")
            if can_decide and rec.user_id != sess.user_id:
                a, b = st.columns(2)
                if a.button("✅ Approve & execute", key=f"ap_{rec.approval_id}"):
                    out = life.complete_approved(rec.approval_id, sess.user_id, role)
                    (st.success if out["status"] == "completed" else st.error)(str(out.get("reason") or out))
                    st.rerun() if out["status"] == "completed" else None
                if b.button("⛔ Reject", key=f"rj_{rec.approval_id}"):
                    out = life.reject_pending(rec.approval_id, sess.user_id, role, "Rejected from the approvals queue")
                    st.warning(str(out))
                    st.rerun()
            elif can_decide:
                st.caption("You cannot decide your own request.")
    st.subheader("History")
    hist = [_row(r, svc) for r in engine.list_all() if can_decide or r.user_id == sess.user_id]
    st.dataframe(hist, use_container_width=True) if hist else st.caption("No approval requests yet.")
