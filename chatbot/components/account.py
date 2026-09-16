"""
VulNet FinTech AI Agent Security Lab - Account View Component.
Displays simulated customer profile, KYC verification status, and synthetic account balances
retrieved directly from the Simulated FinTech Domain Service.
Strictly local and synthetic data.
"""

import streamlit as st
from fintech.service import FintechService


def get_fintech_service() -> FintechService:
    """Retrieve or create the FintechService singleton in session state."""
    if "fintech_service" not in st.session_state:
        st.session_state.fintech_service = FintechService()
    return st.session_state.fintech_service


def render_account_view(current_session) -> None:
    """Renders the simulated customer profile and account overview."""
    cust = current_session.customer_context
    service = get_fintech_service()

    st.markdown("### 🏦 Simulated Customer Account")
    st.caption("Realistic FinTech customer profile and simulated banking balances. Purely synthetic; verified via FintechService.")

    # Retrieve real accounts from the fintech domain service
    try:
        accounts = service.list_customer_accounts(cust.customer_id)
        total_balance = sum(acc.balance for acc in accounts)
    except Exception:
        accounts = []
        total_balance = cust.balance

    # Top KPI cards
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(
            f"""
            <div class="soc-summary-card">
                <div class="metric-lbl">💵 Total Portfolio Balance</div>
                <div class="metric-val" style="color: #10B981;">${total_balance:,.2f} USD</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with c2:
        st.markdown(
            f"""
            <div class="soc-summary-card">
                <div class="metric-lbl">🆔 Customer ID</div>
                <div class="metric-val" style="color: #00E5FF; font-family: monospace;">{cust.customer_id}</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with c3:
        st.markdown(
            f"""
            <div class="soc-summary-card">
                <div class="metric-lbl">📋 KYC Verification</div>
                <div class="metric-val" style="color: #A78BFA;">{cust.kyc_status}</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with c4:
        st.markdown(
            f"""
            <div class="soc-summary-card">
                <div class="metric-lbl">⚡ Linked Accounts</div>
                <div class="metric-val" style="color: #34D399;">{len(accounts)} Verified</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # Detailed Account Attributes & Linked Accounts
    col_left, col_right = st.columns(2)

    with col_left:
        st.markdown("#### 👤 Customer Profile & Linked Accounts")
        st.markdown(
            f"""
            <div style="background: #0D1117; border: 1px solid rgba(255,255,255,0.08); border-radius: 10px; padding: 18px 20px; margin-bottom: 12px;">
                <div style="display:flex; justify-content:space-between; padding: 6px 0; border-bottom: 1px solid rgba(255,255,255,0.05);">
                    <span style="color:#9CA3AF;">Customer Full Name:</span>
                    <span style="font-weight:600; color:#FFFFFF;">{cust.full_name}</span>
                </div>
                <div style="display:flex; justify-content:space-between; padding: 6px 0; border-bottom: 1px solid rgba(255,255,255,0.05);">
                    <span style="color:#9CA3AF;">User Role Tier:</span>
                    <span style="font-weight:600; color:#34D399; text-transform:capitalize;">{cust.user_role} ({cust.tier})</span>
                </div>
                <div style="display:flex; justify-content:space-between; padding: 6px 0;">
                    <span style="color:#9CA3AF;">Data Provider:</span>
                    <span style="color:#00E5FF; font-family:monospace; font-size:12px;">FintechService (In-Memory)</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        st.markdown("##### 💳 Verified Customer Accounts")
        for acc in accounts:
            st.markdown(
                f"""
                <div style="background: #15171C; border: 1px solid rgba(255,255,255,0.07); border-radius: 8px; padding: 12px 16px; margin-bottom: 8px; display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <div style="font-weight:700; color:#FFFFFF; font-size:13px;">{acc.account_type}</div>
                        <div style="font-family:monospace; color:#00E5FF; font-size:11px;">{acc.account_id}</div>
                    </div>
                    <div style="text-align:right;">
                        <div style="font-weight:700; color:#10B981; font-size:14px;">${acc.balance:,.2f} {acc.currency}</div>
                        <span style="font-size:10px; color:#9CA3AF; padding:2px 6px; border-radius:4px; background:rgba(255,255,255,0.05);">{acc.status}</span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

    with col_right:
        st.markdown("#### 🛡️ FinTech Domain Security Guardrails")
        st.markdown(
            """
            <div style="background: #0D1117; border: 1px solid rgba(255,255,255,0.08); border-radius: 10px; padding: 18px 20px;">
                <div style="margin-bottom: 10px; font-size: 13px; color: #ECECF1;">
                    🔒 <strong>Service-Layer Ownership Validation Active:</strong>
                </div>
                <ul style="color: #9CA3AF; font-size: 12px; line-height: 1.8; margin-left: -15px;">
                    <li><strong>Strict Account Ownership:</strong> Customers can only access accounts registered under their customer ID.</li>
                    <li><strong>No Reliance on Agent Prompts:</strong> <code>FintechService</code> raises <code>UnauthorizedAccessError</code> directly if a customer targets another account.</li>
                    <li><strong>Deterministic Sandbox:</strong> Data is completely isolated in local memory with zero external banking connections.</li>
                    <li><strong>No Real Credentials:</strong> Customer authentication operates on synthetic demo session tokens.</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True
        )
