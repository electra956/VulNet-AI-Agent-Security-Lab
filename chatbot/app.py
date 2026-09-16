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
from chatbot.components.sidebar import render_sidebar
from chatbot.components.chat import render_chat_view
from chatbot.components.account import render_account_view
from chatbot.components.transactions import render_transactions_view
from chatbot.components.security_view import render_security_view
from chatbot.components.trace import render_trace_view

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
    st.session_state.security_mode = "secure"

if "orchestrator" not in st.session_state:
    st.session_state.orchestrator = AgentOrchestrator(mode=st.session_state.security_mode)
else:
    if st.session_state.orchestrator.get_mode() != st.session_state.security_mode:
        st.session_state.orchestrator.set_mode(st.session_state.security_mode)

# Active FinTech Session (Authenticated for CUST-001)
auth_service = get_auth_service()
if "active_session_id" not in st.session_state or not auth_service.get_session(st.session_state.get("active_session_id", "")):
    login_info = auth_service.login("alex_morgan", "Cust001Secure!2026")
    auth_sess = auth_service.verify_mfa(login_info["challenge_id"], login_info["mfa_code"])
    st.session_state.active_session_id = auth_sess.session_id

current_session = st.session_state.session_manager.get_session(st.session_state.active_session_id)
if not current_session:
    current_session = st.session_state.session_manager.create_session(user_id="CUST-001", session_id=st.session_state.active_session_id)

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
elif selected_view == "🛡️ Security":
    render_security_view()
elif selected_view == "📑 Agent Trace":
    render_trace_view()
