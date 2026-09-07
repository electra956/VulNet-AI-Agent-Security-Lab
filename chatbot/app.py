import sys
from pathlib import Path

import streamlit as st


# ============================================================
# PROJECT ROOT
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from agents.orchestrator import AgentOrchestrator


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="VulNet AI Agent Security Lab",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# SESSION STATE
# ============================================================

if "messages" not in st.session_state:
    st.session_state.messages = []

if "trace" not in st.session_state:
    st.session_state.trace = []

if "security_mode" not in st.session_state:
    st.session_state.security_mode = "secure"

if "orchestrator" not in st.session_state:
    st.session_state.orchestrator = AgentOrchestrator(
        mode="secure"
    )


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def is_greeting(message):
    greetings = {
        "hi",
        "hello",
        "hey",
        "hii",
        "hiii",
        "helo",
        "good morning",
        "good afternoon",
        "good evening",
        "how are you",
        "what's up",
        "whats up"
    }

    return message.lower().strip() in greetings


def get_greeting_response(message):
    cleaned = message.lower().strip()

    if cleaned == "how are you":
        return (
            "I'm doing well! 🛡️\n\n"
            "I'm the **VulNet AI Agent Security Lab** assistant.\n\n"
            "You can ask me about AI agents, RAG, MCP, "
            "agent security, tools, or security policies."
        )

    return (
        "Hello! 👋🛡️\n\n"
        "Welcome to the **VulNet AI Agent Security Lab**.\n\n"
        "You can ask me about:\n\n"
        "- 🤖 AI Agents\n"
        "- 📚 RAG Security\n"
        "- 🔌 MCP Tools\n"
        "- 🔐 Agent Security\n"
        "- 🛠️ Tool Permissions\n"
        "- 🤝 Agent Communication"
    )


def has_relevant_rag_results(documents):
    if not documents:
        return False

    scores = []

    for document in documents:
        if isinstance(document, dict):
            try:
                scores.append(
                    float(document.get("score", 0))
                )
            except (TypeError, ValueError):
                pass

    if not scores:
        return False

    return max(scores) >= 0.05


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.title("🛡️ VulNet AI Agent")

    st.divider()

    selected_mode = st.radio(
        "Security Mode",
        [
            "🔴 Vulnerable Mode",
            "🟢 Secure Mode"
        ],
        index=(
            0
            if st.session_state.security_mode == "vulnerable"
            else 1
        )
    )

    if selected_mode == "🔴 Vulnerable Mode":
        backend_mode = "vulnerable"
    else:
        backend_mode = "secure"

    if backend_mode != st.session_state.security_mode:

        st.session_state.orchestrator.set_mode(
            backend_mode
        )

        st.session_state.security_mode = backend_mode

    st.caption(
        f"Backend mode: `{st.session_state.security_mode}`"
    )

    st.divider()

    st.subheader("Architecture")

    st.code(
        """
USER
  ↓
CHATBOT
  ↓
SECURITY CONTROLLER
  ↓
RAG
  ↓
MAIN AGENT
  ↓
RESEARCH AGENT
  ↓
ACTION AGENT
  ↓
MCP SERVER
  ↓
SAFE DEMO TOOLS
        """
    )

    st.divider()

    st.subheader("OWASP Agentic Risks")

    st.markdown(
        """
**ASI01** — Agent Goal Hijack

**ASI02** — Tool Misuse

**ASI03** — Identity & Privilege Abuse

**ASI04** — Supply Chain

**ASI05** — Code Execution

**ASI06** — Memory Poisoning

**ASI07** — Agent Communication

**ASI08** — Cascading Failures

**ASI09** — Human Trust

**ASI10** — Rogue Agents
        """
    )

    st.divider()

    if st.button(
        "🗑️ Clear Session",
        use_container_width=True
    ):

        st.session_state.messages = []
        st.session_state.trace = []

        st.session_state.orchestrator.security.clear_events()

        st.rerun()


# ============================================================
# MAIN HEADER
# ============================================================

st.title("🛡️ VulNet AI Agent Security Lab")

st.caption(
    "Chatbot → RAG → AI Agents → MCP → Safe Demo Tools"
)


# ============================================================
# SECURITY STATUS
# ============================================================

if st.session_state.security_mode == "vulnerable":

    st.warning(
        "🔴 **Vulnerable Mode is active.** "
        "Security controls are intentionally relaxed "
        "for controlled security demonstrations."
    )

else:

    st.success(
        "🟢 **Secure Mode is active.** "
        "Security controls are enabled."
    )


# ============================================================
# TABS
# ============================================================

chat_tab, trace_tab, info_tab = st.tabs(
    [
        "💬 Chat",
        "🔍 Request Trace",
        "ℹ️ System Info"
    ]
)


# ============================================================
# CHAT TAB
# ============================================================

with chat_tab:

    st.subheader("AI Security Lab Chatbot")

    # --------------------------------------------------------
    # CHAT HISTORY
    # --------------------------------------------------------

    for message in st.session_state.messages:

        with st.chat_message(message["role"]):
            st.markdown(message["content"])


    # --------------------------------------------------------
    # USER INPUT
    # --------------------------------------------------------

    user_input = st.chat_input(
        "Ask the VulNet AI Agent..."
    )


    if user_input:

        st.session_state.messages.append(
            {
                "role": "user",
                "content": user_input
            }
        )

        with st.chat_message("user"):
            st.markdown(user_input)


        # ====================================================
        # GREETING
        # ====================================================

        if is_greeting(user_input):

            response = get_greeting_response(
                user_input
            )

            with st.chat_message("assistant"):
                st.markdown(response)

            st.session_state.messages.append(
                {
                    "role": "assistant",
                    "content": response
                }
            )

            st.session_state.trace.append(
                {
                    "request": user_input,
                    "mode": st.session_state.security_mode,
                    "type": "Greeting",
                    "security": {},
                    "documents": [],
                    "stages": [
                        "💬 CHATBOT → Greeting detected",
                        "🤖 AGENT PIPELINE → Not required"
                    ]
                }
            )


        # ====================================================
        # REAL REQUEST
        # ====================================================

        else:

            with st.chat_message("assistant"):

                try:

                    with st.spinner(
                        "Processing request through security pipeline..."
                    ):

                        result = (
                            st.session_state.orchestrator.process(
                                user_input
                            )
                        )


                    security_result = result.get(
                        "security",
                        {}
                    )

                    pipeline_status = result.get(
                        "pipeline_status",
                        "completed"
                    )

                    documents = result.get(
                        "retrieved_documents",
                        []
                    )


                    # =========================================
                    # BLOCKED REQUEST
                    # =========================================

                    if pipeline_status == "blocked":

                        scenario = security_result.get(
                            "scenario",
                            "Unknown Security Scenario"
                        )

                        reason = security_result.get(
                            "reason",
                            "Request blocked."
                        )

                        detected_pattern = security_result.get(
                            "detected_pattern",
                            "Unknown"
                        )

                        st.error(
                            "🚫 Request blocked by Security Controller."
                        )

                        st.markdown(
                            "## 🛡️ Security Controller"
                        )

                        st.markdown(
                            "### 🚫 Request Blocked"
                        )

                        st.markdown(
                            "The Security Controller blocked the "
                            "request before it reached the "
                            "agent pipeline."
                        )

                        st.markdown(
                            f"**Security Scenario:** `{scenario}`"
                        )

                        st.markdown(
                            f"**Reason:** {reason}"
                        )

                        st.markdown(
                            f"**Detected Pattern:** "
                            f"`{detected_pattern}`"
                        )

                        st.markdown(
                            "### Pipeline"
                        )

                        st.code(
                            """
USER
  ↓
CHATBOT
  ↓
SECURITY CONTROLLER
  ↓
🚫 BLOCKED
  ↓
RAG NOT EXECUTED
  ↓
AGENTS NOT EXECUTED
  ↓
MCP NOT EXECUTED
                            """
                        )

                        response = (
                            "## 🛡️ Security Controller\n\n"
                            "### 🚫 Request Blocked\n\n"
                            f"**Scenario:** `{scenario}`\n\n"
                            f"**Reason:** {reason}\n\n"
                            f"**Detected Pattern:** "
                            f"`{detected_pattern}`\n\n"
                            "The request was stopped before "
                            "RAG, agents, and MCP execution."
                        )

                        stages = [
                            "💬 CHATBOT → Request received",
                            "🛡️ SECURITY CONTROLLER → Suspicious request detected",
                            f"🚫 BLOCKED → {scenario}",
                            "📚 RAG → Not executed",
                            "🤖 MAIN AGENT → Not executed",
                            "🔍 RESEARCH AGENT → Not executed",
                            "⚡ ACTION AGENT → Not executed",
                            "🔌 MCP → Not executed"
                        ]


                    # =========================================
                    # ALLOWED REQUEST
                    # =========================================

                    else:

                        # -------------------------------------
                        # NO RELEVANT RAG
                        # -------------------------------------

                        if not has_relevant_rag_results(
                            documents
                        ):

                            st.info(
                                "No sufficiently relevant RAG "
                                "context was found."
                            )

                            st.markdown(
                                "## 🛡️ VulNet AI Agent"
                            )

                            st.markdown(
                                f"I received your request:\n\n"
                                f"> {user_input}"
                            )

                            st.markdown(
                                """
However, I could not find sufficiently
relevant information in the local knowledge base.

Try asking about:

- AI agent tools
- Tool permissions
- MCP security
- Agent communication
- Security policies
- RAG security
                                """
                            )

                            response = (
                                "## 🛡️ VulNet AI Agent\n\n"
                                f"I received your request:\n\n"
                                f"> {user_input}\n\n"
                                "No sufficiently relevant "
                                "RAG context was found."
                            )

                            stages = [
                                "💬 CHATBOT → Request received",
                                "🛡️ SECURITY CONTROLLER → Request allowed",
                                "📚 RAG → No relevant context found",
                                "🤖 AGENTS → Pipeline stopped",
                                "🔌 MCP → Not required"
                            ]


                        # -------------------------------------
                        # COMPLETE PIPELINE
                        # -------------------------------------

                        else:

                            main_result = result.get(
                                "main_agent",
                                {}
                            )

                            research_result = result.get(
                                "research_agent",
                                {}
                            )

                            action_result = result.get(
                                "action_agent",
                                {}
                            )

                            mcp_security = result.get(
                                "mcp_security_status",
                                {}
                            )

                            mcp_audit = result.get(
                                "mcp_audit_log",
                                {}
                            )


                            # ==============================
                            # SECURITY
                            # ==============================

                            st.markdown(
                                "## 🛡️ VulNet AI Agent Result"
                            )

                            st.markdown(
                                "### 🛡️ Security Controller"
                            )

                            st.write(
                                f"Mode: `{st.session_state.security_mode}`"
                            )

                            st.write(
                                f"Allowed: "
                                f"`{security_result.get('allowed', True)}`"
                            )

                            st.write(
                                f"Blocked: "
                                f"`{security_result.get('blocked', False)}`"
                            )

                            st.write(
                                f"Scenario: "
                                f"`{security_result.get('scenario') or 'None'}`"
                            )


                            # ==============================
                            # RAG
                            # ==============================

                            st.markdown(
                                "### 📚 RAG"
                            )

                            st.write(
                                f"Retrieved {len(documents)} "
                                "relevant document(s)."
                            )

                            for document in documents:

                                if isinstance(
                                    document,
                                    dict
                                ):

                                    st.write(
                                        f"📄 "
                                        f"{document.get('document', 'Unknown')} "
                                        f"(Score: "
                                        f"{document.get('score', 0)})"
                                    )


                            # ==============================
                            # MAIN AGENT
                            # ==============================

                            st.markdown(
                                "### 🤖 Main Agent"
                            )

                            st.markdown(
                                main_result.get(
                                    "response",
                                    "No Main Agent response available."
                                )
                            )


                            # ==============================
                            # RESEARCH AGENT
                            # ==============================

                            st.markdown(
                                "### 🔍 Research Agent"
                            )

                            st.markdown(
                                research_result.get(
                                    "summary",
                                    research_result.get(
                                        "response",
                                        "Research completed."
                                    )
                                )
                            )

                            findings = research_result.get(
                                "findings",
                                []
                            )

                            if findings:

                                st.markdown(
                                    "**Research Findings:**"
                                )

                                for finding in findings:

                                    if isinstance(
                                        finding,
                                        dict
                                    ):

                                        st.write(
                                            f"📄 "
                                            f"{finding.get('document', 'Unknown')}"
                                        )

                                    else:

                                        st.write(
                                            finding
                                        )


                            # ==============================
                            # ACTION AGENT
                            # ==============================

                            st.markdown(
                                "### ⚡ Action Agent"
                            )

                            st.markdown(
                                action_result.get(
                                    "action",
                                    action_result.get(
                                        "response",
                                        "Action processing completed."
                                    )
                                )
                            )


                            # ==============================
                            # MCP
                            # ==============================

                            st.markdown(
                                "### 🔌 MCP Security Status"
                            )

                            security_data = mcp_security.get(
                                "result",
                                {}
                            )

                            if security_data:

                                st.write(
                                    f"Environment: "
                                    f"`{security_data.get('environment', 'Unknown')}`"
                                )

                                st.write(
                                    f"Production Access: "
                                    f"`{security_data.get('production_access', 'Unknown')}`"
                                )

                                st.write(
                                    f"Network Access: "
                                    f"`{security_data.get('network_access', 'Unknown')}`"
                                )

                                st.write(
                                    f"Credentials Used: "
                                    f"`{security_data.get('credentials_used', 'Unknown')}`"
                                )

                                st.write(
                                    f"Simulation Mode: "
                                    f"`{security_data.get('simulation_mode', 'Unknown')}`"
                                )


                            # ==============================
                            # AUDIT LOG
                            # ==============================

                            st.markdown(
                                "### 📝 MCP Audit Log"
                            )

                            audit_data = mcp_audit.get(
                                "result",
                                {}
                            )

                            if audit_data:

                                st.write(
                                    f"Message: "
                                    f"`{audit_data.get('message', 'Audit log created')}`"
                                )

                                st.write(
                                    f"Location: "
                                    f"`{audit_data.get('location', 'Unknown')}`"
                                )

                                st.write(
                                    f"Real System Modified: "
                                    f"`{audit_data.get('real_system_modified', False)}`"
                                )


                            st.success(
                                "🟢 Pipeline completed safely."
                            )

                            response = (
                                "## 🛡️ VulNet AI Agent Result\n\n"
                                f"Security Mode: "
                                f"`{st.session_state.security_mode}`\n\n"
                                f"RAG Documents: "
                                f"{len(documents)}\n\n"
                                "Pipeline completed safely."
                            )

                            stages = [
                                "💬 CHATBOT → Request received",
                                "🛡️ SECURITY CONTROLLER → Request allowed",
                                f"📚 RAG → {len(documents)} relevant document(s)",
                                "🤖 MAIN AGENT → Analysis completed",
                                "🔍 RESEARCH AGENT → Research completed",
                                "⚡ ACTION AGENT → Safe action approved",
                                "🔌 MCP → Security tools executed",
                                "📝 AUDIT LOG → Created successfully"
                            ]


                    # =================================================
                    # SAVE RESPONSE
                    # =================================================

                    st.session_state.messages.append(
                        {
                            "role": "assistant",
                            "content": response
                        }
                    )


                    # =================================================
                    # SAVE TRACE
                    # =================================================

                    st.session_state.trace.append(
                        {
                            "request": user_input,
                            "mode": st.session_state.security_mode,
                            "type": "AI Agent Pipeline",
                            "security": security_result,
                            "documents": documents,
                            "stages": stages
                        }
                    )


                except Exception as error:

                    error_response = (
                        "## ❌ Pipeline Error\n\n"
                        "The VulNet AI Agent pipeline "
                        "encountered an error.\n\n"
                        f"**Error:** `{error}`\n\n"
                        "Check the WSL terminal for details."
                    )

                    st.error(
                        error_response
                    )

                    st.session_state.messages.append(
                        {
                            "role": "assistant",
                            "content": error_response
                        }
                    )


# ============================================================
# REQUEST TRACE TAB
# ============================================================

with trace_tab:

    st.subheader("🔍 Request Trace")

    if not st.session_state.trace:

        st.info(
            "No requests have been processed yet."
        )

    else:

        for number, trace in enumerate(
            reversed(st.session_state.trace),
            start=1
        ):

            st.markdown(
                f"### Request {number}"
            )

            st.write(
                f"Request: `{trace.get('request', '')}`"
            )

            st.write(
                f"Mode: `{trace.get('mode', 'unknown')}`"
            )

            st.write(
                f"Type: `{trace.get('type', 'unknown')}`"
            )


            security = trace.get(
                "security",
                {}
            )

            if security:

                if security.get(
                    "blocked",
                    False
                ):

                    st.error(
                        "🚫 Security Decision: BLOCKED"
                    )

                    st.write(
                        f"Scenario: "
                        f"{security.get('scenario', 'Unknown')}"
                    )

                    st.write(
                        f"Reason: "
                        f"{security.get('reason', 'Unknown')}"
                    )

                else:

                    st.success(
                        "🟢 Security Decision: ALLOWED"
                    )


            st.markdown(
                "**Pipeline Stages:**"
            )

            for stage in trace.get(
                "stages",
                []
            ):

                st.write(
                    f"- {stage}"
                )


            documents = trace.get(
                "documents",
                []
            )

            if documents:

                with st.expander(
                    "📚 Retrieved RAG Documents"
                ):

                    for document in documents:

                        if isinstance(
                            document,
                            dict
                        ):

                            st.write(
                                f"📄 "
                                f"{document.get('document', 'Unknown')}"
                            )

                            st.write(
                                f"Similarity Score: "
                                f"{document.get('score', 0)}"
                            )

                        else:

                            st.write(
                                document
                            )

            st.divider()


# ============================================================
# SYSTEM INFO TAB
# ============================================================

with info_tab:

    st.subheader(
        "ℹ️ System Information"
    )


    # --------------------------------------------------------
    # ENVIRONMENT
    # --------------------------------------------------------

    st.markdown(
        "### 🛡️ Environment"
    )

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Production Access",
            "DISABLED"
        )

    with col2:
        st.metric(
            "Network Access",
            "DISABLED"
        )

    with col3:
        st.metric(
            "Real Credentials",
            "NONE"
        )

    with col4:
        st.metric(
            "Simulation",
            "ENABLED"
        )


    st.divider()


    # --------------------------------------------------------
    # ARCHITECTURE
    # --------------------------------------------------------

    st.markdown(
        "### 🏗️ Agent Architecture"
    )

    st.code(
        """
USER
  ↓
CHATBOT
  ↓
SECURITY CONTROLLER
  ↓
RAG
  ↓
MAIN AGENT
  ↓
RESEARCH AGENT
  ↓
ACTION AGENT
  ↓
MCP SERVER
  ↓
SAFE DEMO TOOLS
  ↓
AUDIT LOG
        """
    )


    st.divider()


    # --------------------------------------------------------
    # SECURITY MODES
    # --------------------------------------------------------

    st.markdown(
        "### 🔐 Security Modes"
    )

    st.markdown(
        """
### 🔴 Vulnerable Mode

Used for controlled security demonstrations.

Security controls can intentionally allow
vulnerable behavior for testing.

The environment remains local and simulated.

### 🟢 Secure Mode

Security controls are enabled.

Suspicious requests can be detected and blocked
before they reach the agent pipeline.
        """
    )


    st.divider()


    # --------------------------------------------------------
    # OWASP
    # --------------------------------------------------------

    st.markdown(
        "### 🎯 OWASP Agentic AI Security Scenarios"
    )

    owasp = [
        ("ASI01", "Agent Goal Hijack"),
        ("ASI02", "Tool Misuse and Exploitation"),
        ("ASI03", "Identity and Privilege Abuse"),
        ("ASI04", "Agentic Supply Chain Vulnerabilities"),
        ("ASI05", "Unexpected Code Execution"),
        ("ASI06", "Memory & Context Poisoning"),
        ("ASI07", "Insecure Inter-Agent Communication"),
        ("ASI08", "Cascading Failures"),
        ("ASI09", "Human-Agent Trust Exploitation"),
        ("ASI10", "Rogue Agents")
    ]

    for code, name in owasp:

        st.write(
            f"**{code}** — {name}"
        )


    st.divider()


    # --------------------------------------------------------
    # SECURITY PIPELINE
    # --------------------------------------------------------

    st.markdown(
        "### 🔐 Security Pipeline"
    )

    st.code(
        """
USER
  ↓
CHATBOT
  ↓
SECURITY CONTROLLER
  ↓
REQUEST VALIDATION
  ↓
SECURE / VULNERABLE MODE
  ↓
RAG
  ↓
MAIN AGENT
  ↓
RESEARCH AGENT
  ↓
ACTION AGENT
  ↓
MCP SERVER
  ↓
SAFE DEMO TOOLS
  ↓
AUDIT LOG
        """
    )


    st.divider()


    # --------------------------------------------------------
    # CURRENT MODE
    # --------------------------------------------------------

    st.markdown(
        "### 📊 Current Runtime Mode"
    )

    if st.session_state.security_mode == "vulnerable":

        st.error(
            "🔴 Vulnerable Mode"
        )

    else:

        st.success(
            "🟢 Secure Mode"
        )


    st.caption(
        "VulNet AI Agent Security Lab — "
        "Local Educational Environment"
    )