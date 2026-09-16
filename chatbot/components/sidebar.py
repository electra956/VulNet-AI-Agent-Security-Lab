"""
VulNet FinTech AI Agent Security Lab - FinTech Sidebar Component.
Displays simulated customer context, session identifiers, security controls,
and navigation routing.
"""

from typing import Any, Dict
import streamlit as st
from agents.orchestrator import AgentOrchestrator


def render_sidebar(session_manager, current_session) -> str:
    """
    Renders the FinTech-oriented navigation sidebar.
    Returns the selected navigation view name.
    """
    cust = current_session.customer_context

    with st.sidebar:
        # Branding Header
        st.markdown(
            """
            <div style="display: flex; align-items: center; gap: 10px; padding: 4px 0 10px 0;">
                <div style="background: rgba(0, 229, 255, 0.15); border: 1px solid rgba(0, 229, 255, 0.3); border-radius: 8px; padding: 6px 10px; font-size: 18px;">💳</div>
                <div>
                    <div style="font-weight: 700; font-size: 16px; color: #FFFFFF;">VulNet FinTech</div>
                    <div style="font-size: 11px; color: #9CA3AF;">AI Agent Security Lab</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # Customer & Session Info Badge Box
        st.markdown(
            f"""
            <div style="background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.08);
                        border-radius: 8px; padding: 10px 12px; margin-bottom: 12px;">
                <div style="font-size: 10px; font-weight: 700; text-transform: uppercase; color: #00E5FF; letter-spacing: 0.05em; margin-bottom: 6px;">
                    👤 Authenticated Context
                </div>
                <div style="display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 3px;">
                    <span style="color: #9CA3AF;">Customer ID:</span>
                    <span style="font-family: monospace; font-weight: 600; color: #FFFFFF;">{cust.customer_id}</span>
                </div>
                <div style="display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 3px;">
                    <span style="color: #9CA3AF;">Account ID:</span>
                    <span style="font-family: monospace; font-weight: 600; color: #FFFFFF;">{cust.account_id}</span>
                </div>
                <div style="display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 3px;">
                    <span style="color: #9CA3AF;">User Role:</span>
                    <span style="font-weight: 600; color: #34D399; text-transform: capitalize;">{cust.user_role}</span>
                </div>
                <div style="display: flex; justify-content: space-between; font-size: 12px;">
                    <span style="color: #9CA3AF;">Session ID:</span>
                    <span style="font-family: monospace; font-size: 11px; color: #A78BFA;">{current_session.session_id}</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        if st.button("➕ New Session", use_container_width=True):
            new_sess = session_manager.create_session(user_id=cust.customer_id)
            st.session_state.active_session_id = new_sess.session_id
            st.session_state.messages = []
            st.session_state.scenario_result = None
            st.session_state.pending_prompt = None
            st.session_state.orchestrator = AgentOrchestrator(mode=st.session_state.security_mode)
            st.rerun()

        st.markdown("<div style='height: 4px;'></div>", unsafe_allow_html=True)

        # Primary FinTech Navigation Menu
        st.markdown(
            """
            <div style="font-size: 11px; font-weight: 600; text-transform: uppercase; color: #9CA3AF; letter-spacing: 0.05em; margin-bottom: 4px;">
                FinTech Navigation
            </div>
            """,
            unsafe_allow_html=True
        )

        nav_options = [
            "💬 Chat",
            "🏦 Account",
            "💳 Transactions",
            "🛡️ Security",
            "📑 Agent Trace"
        ]

        # Determine index from session_state if previously selected
        current_nav = st.session_state.get("nav_view", "💬 Chat")
        default_idx = nav_options.index(current_nav) if current_nav in nav_options else 0

        selected_nav = st.radio(
            "FinTech Navigation Menu",
            nav_options,
            index=default_idx,
            label_visibility="collapsed"
        )
        st.session_state.nav_view = selected_nav

        st.divider()

        # Security Mode Selection
        st.markdown(
            """
            <div style="font-size: 11px; font-weight: 600; text-transform: uppercase; color: #9CA3AF; letter-spacing: 0.05em; margin-bottom: 6px;">
                Security Mode
            </div>
            """,
            unsafe_allow_html=True
        )

        mode_options = ["🟢 Secure Mode", "🔴 Vulnerable Mode"]
        current_idx = 0 if st.session_state.security_mode == "secure" else 1
        selected_mode = st.radio(
            "Operating Mode",
            mode_options,
            index=current_idx,
            label_visibility="collapsed",
            help="Secure Mode enforces perimeter sanitization, goal anchoring, and RBAC. Vulnerable Mode allows vulnerability demonstrations."
        )

        target_mode = "secure" if "Secure" in selected_mode else "vulnerable"
        if target_mode != st.session_state.security_mode:
            st.session_state.orchestrator.set_mode(target_mode)
            st.session_state.security_mode = target_mode
            st.rerun()

        # Caption
        if st.session_state.security_mode == "secure":
            st.caption("🛡️ **Active Defense**: FinTech perimeter checks, goal anchoring & least-privilege active.")
        else:
            st.caption("⚠️ **Simulation Mode**: Controls relaxed to demonstrate attack impact.")

        st.divider()

        # API Gateway & Telemetry Metrics
        try:
            from chatbot.api_client import VulNetApiClient
            gw_health = VulNetApiClient().check_health()
            gw_badge = "🟢 Connected (FastAPI:8000)" if gw_health.get("available") else "⚪ In-Process Direct"
        except Exception:
            gw_badge = "⚪ In-Process Direct"

        st.caption(f"🔌 API Gateway: `{gw_badge}`")
        events_count = len(st.session_state.orchestrator.security.get_events())
        st.caption(f"📊 Telemetry Events: `{events_count}`")
        st.caption(f"📑 Session Messages: `{len(current_session.messages)}`")
        st.caption(f"🧪 Sandbox: `Strictly Simulated / Local`")

    return selected_nav
