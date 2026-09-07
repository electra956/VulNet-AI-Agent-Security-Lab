import streamlit as st

from agents.orchestrator import AgentOrchestrator


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="VulNet AI Agent Security Lab",
    page_icon="🛡️",
    layout="wide"
)


# --------------------------------------------------
# INITIALIZE COMPLETE AGENT PIPELINE
# --------------------------------------------------

@st.cache_resource
def initialize_components():
    return AgentOrchestrator()


orchestrator = initialize_components()


# --------------------------------------------------
# SESSION STATE
# --------------------------------------------------

if "messages" not in st.session_state:
    st.session_state.messages = []

if "trace" not in st.session_state:
    st.session_state.trace = []


# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------

with st.sidebar:

    st.title("🛡️ VulNet AI Agent")

    st.divider()

    mode = st.radio(
        "Security Mode",
        [
            "🔴 Vulnerable Mode",
            "🟢 Secure Mode"
        ]
    )

    st.divider()

    st.subheader("Architecture")

    st.code("""
USER
  ↓
CHATBOT
  ↓
RAG
  ↓
MAIN AGENT
  ↓
RESEARCH AGENT
  ↓
ACTION AGENT
  ↓
MCP
  ↓
TOOLS
""")

    st.divider()

    if st.button("🗑️ Clear Session"):

        st.session_state.messages = []
        st.session_state.trace = []

        st.rerun()


# --------------------------------------------------
# MAIN PAGE
# --------------------------------------------------

st.title("🛡️ VulNet AI Agent Security Lab")

st.caption(
    "Chatbot → RAG → Main Agent → Research Agent → "
    "Action Agent → MCP → Tools"
)


# --------------------------------------------------
# DISPLAY SELECTED MODE
# --------------------------------------------------

if "Vulnerable" in mode:

    st.warning(
        "🔴 Vulnerable Mode is active. "
        "Security controls will be simulated as disabled."
    )

else:

    st.success(
        "🟢 Secure Mode is active. "
        "Security controls will be simulated as enabled."
    )


# --------------------------------------------------
# TABS
# --------------------------------------------------

chat_tab, trace_tab, info_tab = st.tabs(
    [
        "💬 Chat",
        "🔍 Request Trace",
        "ℹ️ System Info"
    ]
)


# ==================================================
# CHAT TAB
# ==================================================

with chat_tab:

    st.subheader("AI Security Lab Chatbot")

    # ----------------------------------------------
    # DISPLAY OLD MESSAGES
    # ----------------------------------------------

    for message in st.session_state.messages:

        with st.chat_message(message["role"]):
            st.markdown(message["content"])


    # ----------------------------------------------
    # USER INPUT
    # ----------------------------------------------

    user_input = st.chat_input(
        "Enter a message for the AI Agent..."
    )


    # ----------------------------------------------
    # PROCESS USER REQUEST
    # ----------------------------------------------

    if user_input:

        # Store user message

        st.session_state.messages.append(
            {
                "role": "user",
                "content": user_input
            }
        )


        # Display user message

        with st.chat_message("user"):
            st.markdown(user_input)


        # ------------------------------------------
        # PROCESS COMPLETE PIPELINE
        # ------------------------------------------

        with st.chat_message("assistant"):

            with st.status(
                "Processing Agentic AI pipeline...",
                expanded=True
            ) as status:

                # ----------------------------------
                # CHATBOT
                # ----------------------------------

                st.write(
                    "💬 **Chatbot:** Request received"
                )


                # ----------------------------------
                # RUN COMPLETE ORCHESTRATOR
                # ----------------------------------

                st.write(
                    "📚 **RAG:** Searching knowledge base..."
                )

                pipeline_result = orchestrator.process(
                    user_input
                )


                # ----------------------------------
                # EXTRACT PIPELINE RESULTS
                # ----------------------------------

                retrieved_documents = pipeline_result[
                    "retrieved_documents"
                ]

                main_result = pipeline_result[
                    "main_agent"
                ]

                research_result = pipeline_result[
                    "research_agent"
                ]

                action_result = pipeline_result[
                    "action_agent"
                ]


                # ----------------------------------
                # RAG STATUS
                # ----------------------------------

                st.write(
                    f"📄 **RAG:** Retrieved "
                    f"{len(retrieved_documents)} document(s)"
                )


                # ----------------------------------
                # MAIN AGENT STATUS
                # ----------------------------------

                st.write(
                    "🤖 **Main Agent:** Analysis completed"
                )


                # ----------------------------------
                # RESEARCH AGENT STATUS
                # ----------------------------------

                st.write(
                    "🔍 **Research Agent:** Research completed"
                )


                # ----------------------------------
                # ACTION AGENT STATUS
                # ----------------------------------

                st.write(
                    "⚡ **Action Agent:** "
                    "Simulated action completed"
                )


                # ----------------------------------
                # MCP / TOOLS - FUTURE
                # ----------------------------------

                st.write(
                    "🔌 **MCP:** Pending"
                )

                st.write(
                    "🛠️ **Tools:** Pending"
                )


                # ----------------------------------
                # COMPLETE STATUS
                # ----------------------------------

                status.update(
                    label="Pipeline completed successfully",
                    state="complete",
                    expanded=False
                )


            # --------------------------------------
            # BUILD FINAL RESPONSE
            # --------------------------------------

            response = f"""
# 🤖 VulNet AI Agent Result

---

{main_result["response"]}

---

## 🔍 Research Agent

**Status:** {research_result["status"]}

{research_result["summary"]}

**Documents Analyzed:** {research_result["documents_analyzed"]}

---

## ⚡ Action Agent

**Status:** {action_result["status"]}

**Decision:** {action_result["decision"]}

{action_result["action"]}
"""

            st.markdown(response)


        # ------------------------------------------
        # STORE ASSISTANT RESPONSE
        # ------------------------------------------

        st.session_state.messages.append(
            {
                "role": "assistant",
                "content": response
            }
        )


        # ------------------------------------------
        # ADD COMPLETE REQUEST TRACE
        # ------------------------------------------

        st.session_state.trace.append(
            {
                "request": user_input,

                "mode": mode,

                "retrieved_documents": retrieved_documents,

                "main_agent_result": main_result,

                "research_agent_result": research_result,

                "action_agent_result": action_result,

                "stages": [

                    "💬 CHATBOT — Request received",

                    (
                        f"📚 RAG — "
                        f"{len(retrieved_documents)} "
                        f"document(s) retrieved"
                    ),

                    "🤖 MAIN AGENT — Analysis completed",

                    "🔍 RESEARCH AGENT — Research completed",

                    "⚡ ACTION AGENT — Simulated action completed",

                    "🔌 MCP — Pending",

                    "🛠️ TOOLS — Pending"
                ]
            }
        )


# ==================================================
# REQUEST TRACE TAB
# ==================================================

with trace_tab:

    st.subheader("🔍 Request Processing Trace")


    if not st.session_state.trace:

        st.info(
            "No requests processed yet. "
            "Send a message from the Chat tab."
        )


    else:

        latest_trace = st.session_state.trace[-1]


        # ------------------------------------------
        # REQUEST INFORMATION
        # ------------------------------------------

        st.write(
            f"### Request: "
            f"`{latest_trace['request']}`"
        )

        st.write(
            f"### Mode: "
            f"{latest_trace['mode']}"
        )

        st.divider()


        # ------------------------------------------
        # PIPELINE
        # ------------------------------------------

        st.subheader("🔄 Pipeline")

        for stage in latest_trace["stages"]:
            st.write(f"➡️ {stage}")


        st.divider()


        # ------------------------------------------
        # RETRIEVED DOCUMENTS
        # ------------------------------------------

        st.subheader("📚 Retrieved Documents")

        retrieved_documents = latest_trace[
            "retrieved_documents"
        ]


        if not retrieved_documents:

            st.warning(
                "No documents were retrieved."
            )

        else:

            for document in retrieved_documents:

                document_name = document.get(
                    "document",
                    "Unknown Document"
                )

                score = document.get(
                    "score",
                    0
                )

                st.write(
                    f"📄 **{document_name}** "
                    f"— Similarity Score: `{score}`"
                )


        st.divider()


        # ------------------------------------------
        # MAIN AGENT RESULT
        # ------------------------------------------

        st.subheader("🤖 Main Agent Result")

        main_result = latest_trace[
            "main_agent_result"
        ]

        st.write(
            f"**Status:** {main_result['status']}"
        )

        st.write(
            f"**Decision:** {main_result['decision']}"
        )

        st.write(
            f"**Documents Used:** "
            f"{main_result['documents_used']}"
        )


        st.divider()


        # ------------------------------------------
        # RESEARCH AGENT RESULT
        # ------------------------------------------

        st.subheader("🔍 Research Agent Result")

        research_result = latest_trace[
            "research_agent_result"
        ]

        st.write(
            f"**Status:** "
            f"{research_result['status']}"
        )

        st.write(
            f"**Summary:** "
            f"{research_result['summary']}"
        )

        st.write(
            f"**Documents Analyzed:** "
            f"{research_result['documents_analyzed']}"
        )


        st.divider()


        # ------------------------------------------
        # ACTION AGENT RESULT
        # ------------------------------------------

        st.subheader("⚡ Action Agent Result")

        action_result = latest_trace[
            "action_agent_result"
        ]

        st.write(
            f"**Status:** "
            f"{action_result['status']}"
        )

        st.write(
            f"**Decision:** "
            f"{action_result['decision']}"
        )

        st.write(
            f"**Documents Analyzed:** "
            f"{action_result.get('documents_analyzed', 0)}"
        )


# ==================================================
# SYSTEM INFO TAB
# ==================================================

with info_tab:

    st.subheader("System Components")

    col1, col2 = st.columns(2)


    with col1:

        st.markdown("""
### 💬 Chatbot

**Status:** 🟢 Running

Receives user requests and displays results.
""")


        st.markdown("""
### 📚 RAG

**Status:** 🟢 Connected

Retrieves documents from the local knowledge base using TF-IDF similarity search.
""")


        st.markdown("""
### 🤖 Main Agent

**Status:** 🟢 Connected

Analyzes user requests using retrieved RAG context.
""")


        st.markdown("""
### 🔍 Research Agent

**Status:** 🟢 Connected

Analyzes retrieved documents and extracts relevant findings.
""")


    with col2:

        st.markdown("""
### ⚡ Action Agent

**Status:** 🟢 Connected

Makes safe simulated decisions based on research findings.
""")


        st.markdown("""
### 🔌 MCP

**Status:** 🟡 Not Connected Yet

The next component to be integrated.
""")


        st.markdown("""
### 🛠️ Tools

**Status:** 🟡 Not Connected Yet

Safe local demonstration tools will be added through MCP.
""")


        st.markdown("""
### 🔐 Security Modes

**🔴 Vulnerable Mode**

Used for controlled security demonstrations.

**🟢 Secure Mode**

Will demonstrate validation, authorization, and safer controls.
""")