"""
VulNet FinTech AI Agent Security Lab - Main Web Application.
Level 2 FinTech Chatbot & Security Orchestration Interface.

Preserves all Level 1 security mechanisms (Security Controller, RAG, Multi-Agent, MCP)
while providing simulated customer contexts, session management, and FinTech workflows.
"""

import sys
from pathlib import Path
import streamlit as st

# ============================================================
# PROJECT ROOT CONFIGURATION
# ============================================================
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.orchestrator import AgentOrchestrator
from chatbot.sessions.session_manager import SessionManager, CustomerContext, get_shared_session_manager
from auth.authentication import get_auth_service
from chatbot.components.login import is_authenticated, render_login_page
from chatbot.components.sidebar import render_sidebar
from security import settings
from chatbot.components.chat import render_chat_view
from chatbot.components.account import render_account_view
from chatbot.components.transactions import render_transactions_view
from chatbot.components.security_view import render_security_view
from chatbot.components.trace import render_trace_view
from chatbot.components.audit_view import render_audit_view
from chatbot.components import lab_views

# ============================================================
# PAGE CONFIGURATION
# ============================================================
st.set_page_config(
    page_title="VulNet FinTech AI Agent",
    page_icon="💳",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load Style CSS
CSS_FILE = Path(__file__).resolve().parent / "styles.css"
if CSS_FILE.exists():
    with open(CSS_FILE, "r", encoding="utf-8") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# ============================================================
# SESSION STATE INITIALIZATION
# ============================================================
if "session_manager" not in st.session_state:
    st.session_state.session_manager = get_shared_session_manager()

if "security_mode" not in st.session_state:
    st.session_state.security_mode = settings.default_security_mode()

if "orchestrator" not in st.session_state:
    st.session_state.orchestrator = AgentOrchestrator(mode=st.session_state.security_mode)
else:
    if st.session_state.orchestrator.get_mode() != st.session_state.security_mode:
        st.session_state.orchestrator.set_mode(st.session_state.security_mode)

# Authentication gate: nothing else renders until the user has signed in (password + MFA)
auth_service = get_auth_service()
if not is_authenticated(auth_service):
    render_login_page(auth_service)
    st.stop()

current_session = st.session_state.session_manager.get_session(st.session_state.active_session_id)
if not current_session:
    current_session = st.session_state.session_manager.create_session(
        user_id=auth_service.get_session(st.session_state.active_session_id).user_id,
        session_id=st.session_state.active_session_id,
    )

# Persistent chat history: restore the user's last conversation once per browser session
from chatbot.sessions.history_store import ChatHistoryStore
_history = ChatHistoryStore()
if not st.session_state.get("history_loaded"):
    _saved = _history.load(current_session.user_id)
    if _saved and not current_session.messages:
        current_session.messages = list(_saved["messages"])
        current_session.conversation_id = _saved.get("conversation_id", current_session.conversation_id)
    st.session_state.history_loaded = True

if "messages" not in st.session_state:
    st.session_state.messages = current_session.get_messages()

if "trace" not in st.session_state:
    st.session_state.trace = []

if "scenario_result" not in st.session_state:
    st.session_state.scenario_result = None

if "pending_prompt" not in st.session_state:
    st.session_state.pending_prompt = None

# ============================================================
# RENDER SIDEBAR & NAVIGATION
# ============================================================
selected_view = render_sidebar(st.session_state.session_manager, current_session)

# ============================================================
# DISPATCH ACTIVE VIEW
# ============================================================
if selected_view == "💬 Chat":
    render_chat_view(st.session_state.session_manager, current_session)
elif selected_view == "🏦 Account":
    render_account_view(current_session)
elif selected_view == "💳 Transactions":
    render_transactions_view(current_session)
elif selected_view == "🚦 Security Gateway":
    lab_views.render_gateway_view()
elif selected_view == "📑 Agent Trace":
    render_trace_view()
elif selected_view == "👥 Users":
    lab_views.render_users_view()
elif selected_view == "✅ Approvals":
    from chatbot.components.approvals import render_approvals_view
    render_approvals_view()
elif selected_view == "🤖 Agents":
    lab_views.render_agents_view()
elif selected_view == "📚 RAG":
    lab_views.render_rag_view()
elif selected_view == "🧠 Memory":
    lab_views.render_memory_view()
elif selected_view == "🧰 MCP Tools":
    lab_views.render_mcp_tools_view()
elif selected_view == "⚔️ Attack Lab":
    lab_views.render_attack_lab()
elif selected_view == "📜 Audit":
    render_audit_view()
elif selected_view == "📄 Reports":
    lab_views.render_reports_view_lab()
elif selected_view == "🩺 System Health":
    lab_views.render_health_view()
elif selected_view.startswith("OWASP ASI"):
    lab_views.render_owasp_page(selected_view.split(" ")[1])

# Persist after every interaction (cheap; atomic write)
_history.save(current_session.user_id, current_session.conversation_id, current_session.get_messages())
