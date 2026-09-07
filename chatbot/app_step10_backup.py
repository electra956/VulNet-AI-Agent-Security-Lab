import streamlit as st

from rag.rag_engine import RAGEngine
from agents.main_agent import MainAgent


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="VulNet AI Agent Security Lab",
    page_icon="🛡️",
    layout="wide"
)


# --------------------------------------------------
# INITIALIZE COMPONENTS
# --------------------------------------------------

@st.cache_resource
def initialize_components():

    rag_engine = RAGEngine(
        knowledge_path="rag/knowledge"
    )

    main_agent = MainAgent()

    return rag_engine, main_agent


rag_engine, main_agent = initialize_components()


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
AGENT ↔ AGENT
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
    "Chatbot → RAG → AI Agent → Agent-to-Agent → MCP → Tools"
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

            st.markdown(
                message["content"]
            )


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
        # PROCESS PIPELINE
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
                # RAG
                # ----------------------------------

                st.write(
                    "📚 **RAG:** Searching knowledge base..."
                )

                retrieved_documents = rag_engine.search(
                    user_input
                )

                st.write(
                    f"📄 **RAG:** Retrieved "
                    f"{len(retrieved_documents)} document(s)"
                )


                # ----------------------------------
                # MAIN AGENT
                # ----------------------------------

                st.write(
                    "🤖 **Main Agent:** Analyzing retrieved context..."
                )

                result = main_agent.analyze(
                    user_input,
                    retrieved_documents
                )


                st.write(
                    "✅ **Main Agent:** Analysis completed"
                )


                # ----------------------------------
                # FUTURE COMPONENTS
                # ----------------------------------

                st.write(
                    "🤝 **Agent-to-Agent:** Pending"
                )

                st.write(
                    "🔌 **MCP:** Pending"
                )

                st.write(
                    "🛠️ **Tools:** Pending"
                )


                status.update(
                    label="Pipeline completed successfully",
                    state="complete",
                    expanded=False
                )


            # --------------------------------------
            # DISPLAY REAL MAIN AGENT RESPONSE
            # --------------------------------------

            response = result["response"]

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
        # ADD REAL REQUEST TRACE
        # ------------------------------------------

        st.session_state.trace.append(
            {
                "request": user_input,
                "mode": mode,
                "retrieved_documents": retrieved_documents,
                "main_agent_result": result,
                "stages": [

                    "💬 CHATBOT — Request received",

                    f"📚 RAG — "
                    f"{len(retrieved_documents)} document(s) retrieved",

                    "🤖 MAIN AGENT — Analysis completed",

                    "🤝 AGENT-TO-AGENT — Pending",

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

        st.subheader("Pipeline")

        for stage in latest_trace["stages"]:

            st.write(
                f"➡️ {stage}"
            )


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
            f"**Status:** "
            f"{main_result['status']}"
        )

        st.write(
            f"**Decision:** "
            f"{main_result['decision']}"
        )

        st.write(
            f"**Documents Used:** "
            f"{main_result['documents_used']}"
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


    with col2:

        st.markdown("""
### 🤝 Agent-to-Agent

**Status:** 🟡 Not Connected Yet

Will enable controlled communication between specialized agents.
""")


        st.markdown("""
### 🔌 MCP

**Status:** 🟡 Not Connected Yet

Will provide controlled demo tools.
""")


        st.markdown("""
### 🛠️ Tools

**Status:** 🟡 Not Connected Yet

Safe simulated tools will be added.
""")