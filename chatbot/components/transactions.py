"""
VulNet FinTech AI Agent Security Lab - Transactions View Component.
Displays simulated customer transactions and ledger activity retrieved
directly from the Simulated FinTech Domain Service.
Strictly local and synthetic data.
"""

import streamlit as st
from fintech.service import FintechService


def get_fintech_service() -> FintechService:
    """Retrieve or create the FintechService singleton in session state."""
    if "fintech_service" not in st.session_state:
        st.session_state.fintech_service = FintechService()
    return st.session_state.fintech_service


def render_transactions_view(current_session) -> None:
    """Renders simulated transaction history for the active customer."""
    cust = current_session.customer_context
    service = get_fintech_service()

    st.markdown("### 💳 Simulated Transaction History")
    st.caption(f"Recent ledger activity for Account `{cust.account_id}` ({cust.customer_id}). Retrieved from FintechService.")

    try:
        transactions = service.get_transaction_history(cust.customer_id, cust.account_id)
    except Exception as exc:
        st.error(f"Error loading transactions: {str(exc)}")
        transactions = []

    # KPI row
    total_credits = sum(t.amount for t in transactions if t.destination_account == cust.account_id)
    total_debits = sum(abs(t.amount) for t in transactions if t.source_account == cust.account_id)

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(
            f"""
            <div class="soc-summary-card">
                <div class="metric-lbl">📈 Total Inbound Credits</div>
                <div class="metric-val" style="color: #10B981;">+${total_credits:,.2f} USD</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with c2:
        st.markdown(
            f"""
            <div class="soc-summary-card">
                <div class="metric-lbl">📉 Total Outbound Debits</div>
                <div class="metric-val" style="color: #EF4444;">-${total_debits:,.2f} USD</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with c3:
        st.markdown(
            f"""
            <div class="soc-summary-card">
                <div class="metric-lbl">📑 Total Ledger Records</div>
                <div class="metric-val" style="color: #00E5FF;">{len(transactions)} Simulated</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
    st.markdown("#### 📋 Simulated Transactions Ledger")

    if not transactions:
        st.info(f"No transactions recorded for account {cust.account_id}.")
        return

    for txn in transactions:
        is_credit = (txn.destination_account == cust.account_id)
        amt_color = "#10B981" if is_credit else "#EF4444"
        amt_sign = "+" if is_credit else "-"
        type_icon = "📥" if is_credit else "📤"

        st.markdown(
            f"""
            <div style="background: #0D1117; border: 1px solid rgba(255,255,255,0.07); border-radius: 10px;
                        padding: 12px 18px; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center;">
                <div style="display: flex; align-items: center; gap: 14px;">
                    <span style="font-size: 20px;">{type_icon}</span>
                    <div>
                        <div style="font-weight: 600; font-size: 13px; color: #FFFFFF;">{txn.description}</div>
                        <div style="font-size: 11px; color: #9CA3AF; margin-top: 2px;">
                            <span>ID: <code style="color:#00E5FF;">{txn.transaction_id}</code></span> &bull; 
                            <span>Category: <code>{txn.category}</code></span> &bull; 
                            <span>{txn.timestamp}</span>
                        </div>
                    </div>
                </div>
                <div style="text-align: right;">
                    <div style="font-size: 14px; font-weight: 700; color: {amt_color};">
                        {amt_sign}${abs(txn.amount):,.2f}
                    </div>
                    <span style="font-size: 10px; font-weight: 600; padding: 2px 6px; border-radius: 4px;
                                 background: rgba(16,185,129,0.15); color: #10B981; border: 1px solid rgba(16,185,129,0.3);">
                        {txn.status}
                    </span>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
