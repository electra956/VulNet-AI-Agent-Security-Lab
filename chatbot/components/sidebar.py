"""
VulNet FinTech AI Agent Security Lab - FinTech Sidebar Component.
Displays simulated customer context, session identifiers, security controls,
and navigation routing.
"""

import uuid
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

        from chatbot.sessions.history_store import ChatHistoryStore
        history = ChatHistoryStore()

        def _reset_chat_state() -> None:
            st.session_state.scenario_result = None
            st.session_state.pending_prompt = None
            st.session_state.orchestrator = AgentOrchestrator(mode=st.session_state.security_mode)
            st.session_state.nav_view = "💬 Chat"
            st.session_state.nav_radio = "💬 Chat"
            st.session_state.more_pick = "—"

        if st.button("➕ New Chat", use_container_width=True):
            # The current chat is already saved after every turn; just start a fresh one.
            history.save(current_session.user_id, current_session.conversation_id, current_session.get_messages())
            current_session.messages.clear()
            current_session.conversation_id = f"CONV-{uuid.uuid4().hex[:8].upper()}"
            st.session_state.messages = []
            _reset_chat_state()
            st.rerun()

        past = [c for c in history.list(current_session.user_id)]
        if past:
            st.markdown(
                """<div style="font-size: 11px; font-weight: 600; text-transform: uppercase; color: #9CA3AF;
                letter-spacing: 0.05em; margin: 8px 0 2px 0;">Chat History</div>""",
                unsafe_allow_html=True,
            )
            for c in past[:15]:
                active = c["conversation_id"] == current_session.conversation_id
                col_open, col_del = st.columns([5, 1])
                with col_open:
                    if st.button(("● " if active else "") + c["title"], key=f"hist_open_{c['conversation_id']}",
                                 use_container_width=True, help=f"{c['count']} messages", disabled=active):
                        saved = history.load(current_session.user_id, c["conversation_id"])
                        if saved:
                            history.save(current_session.user_id, current_session.conversation_id, current_session.get_messages())
                            current_session.messages = list(saved["messages"])
                            current_session.conversation_id = c["conversation_id"]
                            st.session_state.messages = current_session.get_messages()
                            _reset_chat_state()
                            st.rerun()
                with col_del:
                    if st.button("🗑", key=f"hist_del_{c['conversation_id']}", help="Delete this chat"):
                        history.delete(current_session.user_id, c["conversation_id"])
                        if active:
                            current_session.messages.clear()
                            current_session.conversation_id = f"CONV-{uuid.uuid4().hex[:8].upper()}"
                            st.session_state.messages = []
                        st.rerun()

        if st.button("🚪 Sign out", use_container_width=True):
            from chatbot.components.profile import sign_out
            sign_out()

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

        nav_options = ["💬 Chat", "💸 Pay", "👤 Profile", "🏦 Account", "💳 Transactions"]
        more_pages = [
            "👥 Users", "✅ Approvals", "🤖 Agents", "📚 RAG", "🧠 Memory", "🧰 MCP Tools",
            "🚦 Security Gateway", "⚔️ Attack Lab", "📑 Agent Trace", "📜 Audit", "📄 Reports", "🩺 System Health",
        ]
        owasp_pages = [
            "ASI01 · Agent Goal Hijack", "ASI02 · Tool Misuse & Exploitation", "ASI03 · Identity & Privilege Abuse",
            "ASI04 · Agentic Supply Chain", "ASI05 · Unexpected Code Execution", "ASI06 · Memory & Context Poisoning",
            "ASI07 · Insecure Inter-Agent Comms", "ASI08 · Cascading Failures", "ASI09 · Human-Agent Trust Exploitation",
            "ASI10 · Rogue Agents",
        ]
        more_options = ["—"] + more_pages + owasp_pages

        def _clear_more() -> None:
            st.session_state.more_pick = "—"

        def _clear_main() -> None:
            st.session_state.nav_radio = None

        current_nav = st.session_state.get("nav_view", "💬 Chat")
        default_idx = nav_options.index(current_nav) if current_nav in nav_options else 0

        selected_nav = st.radio(
            "FinTech Navigation Menu",
            nav_options,
            index=0 if "nav_radio" in st.session_state else default_idx,  # state wins once the widget exists
            label_visibility="collapsed",
            key="nav_radio",
            on_change=_clear_more,
        )
        st.markdown(
            """
            <div style="font-size: 11px; font-weight: 600; text-transform: uppercase; color: #9CA3AF; letter-spacing: 0.05em; margin: 8px 0 2px 0;">
                Other
            </div>
            """,
            unsafe_allow_html=True
        )
        more_pick = st.selectbox("Other pages", more_options, key="more_pick", label_visibility="collapsed",
                                 on_change=_clear_main)
        if more_pick != "—":
            selected_nav = ("OWASP " + more_pick.split(" ")[0]) if more_pick.startswith("ASI") else more_pick
        elif selected_nav is None:
            selected_nav = current_nav if current_nav in nav_options else "💬 Chat"
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

        from security import settings
        mode_options = ["🟢 Secure Mode", "🔴 Vulnerable Mode"] if settings.allow_client_mode_override() else ["🟢 Secure Mode"]
        current_idx = 0 if (st.session_state.security_mode == "secure" or len(mode_options) == 1) else 1
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

        # LLM Engine & API Gateway Status
        from llm.ollama_client import get_ollama_client
        ollama_status = get_ollama_client().check_health()
        if ollama_status.connected:
            ollama_badge = f"🟢 Ollama: {ollama_status.model}"
        else:
            ollama_badge = "⚠️ Local Fallback (Simulated)"

        st.caption(f"🤖 LLM Engine: `{ollama_badge}`")

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
