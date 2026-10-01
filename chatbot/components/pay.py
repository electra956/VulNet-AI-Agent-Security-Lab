"""
VulNet FinTech AI Agent Security Lab - Pay View (UPI-style wallet screen).
Balance, send money to a contact or account, and recent activity. Every payment goes through the
same guarded orchestrator pipeline as the chat assistant (ownership, risk, approval, audit).
Strictly local and synthetic: no real money moves.
"""

import time

import streamlit as st
from fintech.beneficiaries import get_beneficiary_registry
from fintech.service import get_shared_fintech_service


def _contacts(customer_id, own_account_ids):
    """Trusted payees (plus the customer's own other accounts is handled by the From/To pickers)."""
    repo = get_shared_fintech_service().repository
    names = {a: c.name for c in repo.customers.values() for a in c.account_ids}
    return [(f"{names.get(a, 'Payee')} · {a}", a) for a in get_beneficiary_registry().list(customer_id)
            if a not in own_account_ids]


def _render_trusted_payees(customer_id, own_ids):
    reg = get_beneficiary_registry()
    repo = get_shared_fintech_service().repository
    with st.expander("🛡️ Trusted payees", expanded=False):
        st.caption("In Secure Mode you can only send money to your own accounts or to a trusted payee. "
                   "Payees can only be added here, not through chat.")
        for acc in reg.list(customer_id):
            c1, c2 = st.columns([4, 1])
            c1.markdown(f"`{acc}`")
            if c2.button("Remove", key=f"payee_rm_{acc}"):
                reg.remove(customer_id, acc)
                st.rerun()
        new_acc = st.text_input("Add payee account ID", placeholder="ACC-2002", key="payee_new").strip().upper()
        if st.button("Add trusted payee", key="payee_add"):
            if new_acc in own_ids:
                st.info("That is already your own account.")
            elif repo.get_account(new_acc) is None:
                st.error(f"Account {new_acc or '(blank)'} was not found.")
            else:
                reg.add(customer_id, new_acc)
                st.success(f"{new_acc} added to your trusted payees.")
                st.rerun()


def render_pay_view(current_session) -> None:
    cust = current_session.customer_context
    service = get_shared_fintech_service()
    own_ids = list(cust.account_ids or [cust.account_id])

    st.markdown("### 💸 Pay & Transfer")
    st.caption("Send money, check your balance and see recent activity. You can also just ask the Chat assistant, "
               "e.g. *\"Send $25 to ACC-2001\"*, *\"What's my balance?\"*, *\"Show my last transactions\"*.")

    try:
        accounts = [service.get_account(cust.customer_id, a) for a in own_ids]
    except Exception as exc:
        st.error(f"Could not load accounts: {exc}")
        return

    total = sum(a.balance for a in accounts)
    st.markdown(
        f"""<div style="background:linear-gradient(135deg,#4F46E5,#7C3AED); border-radius:14px; padding:20px 24px; margin-bottom:14px;">
            <div style="color:#E0E7FF; font-size:12px;">Total balance</div>
            <div style="color:#FFFFFF; font-size:32px; font-weight:700;">${total:,.2f}</div>
            <div style="color:#C7D2FE; font-size:12px; margin-top:4px;">{' · '.join(f'{a.account_id}: ${a.balance:,.2f}' for a in accounts)}</div>
        </div>""",
        unsafe_allow_html=True,
    )

    col_send, col_recent = st.columns([1, 1])

    with col_send:
        st.markdown("#### 📤 Send money")
        contacts = _contacts(cust.customer_id, own_ids)
        labels = [c[0] for c in contacts] + ["Other account…"]
        choice = st.selectbox("To", labels, key="pay_to")
        if choice == "Other account…":
            dest = st.text_input("Account ID", placeholder="ACC-2001", key="pay_dest").strip().upper()
        else:
            dest = dict(contacts)[choice]
        src = st.selectbox("From", own_ids, key="pay_from")
        amount = st.number_input("Amount (USD)", min_value=0.0, step=5.0, format="%.2f", key="pay_amount")
        note = st.text_input("Note (optional)", key="pay_note", max_chars=60)

        if choice == "Other account…" and dest and dest not in own_ids and not get_beneficiary_registry().is_trusted(cust.customer_id, dest):
            st.warning(f"{dest} is not a trusted payee. In Secure Mode this payment will be blocked until you add it below.")
        if st.button("Pay now", type="primary", use_container_width=True, key="pay_submit"):
            if not dest or amount <= 0:
                st.warning("Enter a destination account and an amount above 0.")
            elif service.repository.get_account(dest) is None:
                st.error(f"Account {dest} was not found.")
            else:
                req_id = f"REQ-PAY-{int(time.time() * 1000) % 10**9}"
                session_ctx = current_session.create_request_context(request_id=req_id)
                result = st.session_state.orchestrator.process(
                    f"Transfer ${amount:,.2f} from {src} to {dest}" + (f" ({note})" if note else ""),
                    session_context=session_ctx,
                )
                text = result.get("final_response") or result.get("response") or "Done."
                (st.success if result.get("status") in ("completed", "COMPLETED") else st.info)("Payment processed")
                st.markdown(text, unsafe_allow_html=True)

    with col_recent:
        _render_trusted_payees(cust.customer_id, own_ids)
        st.markdown("#### 🕘 Recent activity")
        txns = []
        for a in accounts:
            try:
                txns += service.get_transaction_history(cust.customer_id, a.account_id)
            except Exception:
                pass
        seen, rows = set(), []
        for t in sorted(txns, key=lambda t: str(getattr(t, "created_at", "")), reverse=True):
            if t.transaction_id not in seen:
                seen.add(t.transaction_id)
                rows.append(t)
        if not rows:
            st.info("No transactions yet.")
        for t in rows[:8]:
            credit = t.destination_account_id in own_ids and t.source_account_id not in own_ids
            sign, color = ("+", "#10B981") if credit else ("-", "#EF4444")
            st.markdown(
                f"""<div style="display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid rgba(255,255,255,0.06);">
                    <div><div style="font-weight:600;">{t.description}</div>
                    <div style="font-size:11px; color:#9CA3AF;">{t.transaction_id} · {t.status}</div></div>
                    <div style="font-weight:700; color:{color};">{sign}${abs(t.amount):,.2f}</div></div>""",
                unsafe_allow_html=True,
            )
