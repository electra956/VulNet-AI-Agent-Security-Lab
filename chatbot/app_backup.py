import sys
from pathlib import Path

import streamlit as st


# --------------------------------------------------
# PROJECT PATH SETUP
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from rag.rag_engine import RAGEngine


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="VulNet AI Agent Security Lab",
    page_icon="🛡️",
    layout="wide"
)


# --------------------------------------------------
# LOAD RAG ENGINE
# --------------------------------------------------

@st.cache_resource
def get_rag_engine():
    return RAGEngine(
        knowledge_path=PROJECT_ROOT / "rag" / "knowledge"
    )


rag_engine = get_rag_engine()


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
            st.markdown(message["content"])


    # ----------------------------------------------
    # USER INPUT
    # ----------------------------------------------

    user_input = st.chat_input(
        "Enter a message for the AI Agent..."
    )


    if user_input:

        # ------------------------------------------
        # STORE USER MESSAGE
        # ------------------------------------------

        st.session_state.messages.append(
            {
                "role": "user",
                "content": user_input
            }
        )


        with st.chat_message("user"):
            st.markdown(user_input)


        # ------------------------------------------
        # RAG RETRIEVAL
        # ------------------------------------------

        rag_results = rag_engine.search(
            user_input,
            top_k=2
        )


        # ------------------------------------------
        # BUILD RAG CONTEXT
        # ------------------------------------------

        retrieved_context = ""

        if rag_results:

            for result in rag_results:

                retrieved_context += (
                    f"\n\n### 📄 {result['document']}\n"
                    f"**Similarity Score:** "
                    f"{result['score']}\n\n"
                    f"{result['content']}"
                )

        else:

            retrieved_context = (
                "No relevant documents were found "
                "in the knowledge base."
            )


        # ------------------------------------------
        # RESPONSE
        # ------------------------------------------

        response = f"""
## Request Processed

**Current Mode:** {mode}

### 📚 RAG Retrieval Results

{retrieved_context}

---

### 🔄 Pipeline Status

1. 💬 **Chatbot:** Request received ✅
2. 📚 **RAG:** Documents retrieved ✅
3. 🤖 **Main Agent:** Not connected yet ⏳
4. 🤝 **Agent-to-Agent:** Not connected yet ⏳
5. 🔌 **MCP:** Not connected yet ⏳
6. 🛠️ **Tools:** Not connected yet ⏳
"""


        # ------------------------------------------
        # STORE ASSISTANT RESPONSE
        # ------------------------------------------

        st.session_state.messages.append(
            {
                "role": "assistant",
                "content": response
            }
        )


        with st.chat_message("assistant"):
            st.markdown(response)


        # ------------------------------------------
        # CREATE TRACE
        # ------------------------------------------

        retrieved_documents = []

        for result in rag_results:

            retrieved_documents.append(
                {
                    "document": result["document"],
                    "score": result["score"]
                }
            )


        st.session_state.trace.append(
            {
                "request": user_input,
                "mode": mode,

                "stages": [
                    "CHATBOT ✅ Request received",
                    "RAG ✅ Documents retrieved",
                    "MAIN AGENT ⏳ Pending",
                    "A2A ⏳ Pending",
                    "MCP ⏳ Pending",
                    "TOOLS ⏳ Pending"
                ],

                "rag_results": retrieved_documents
            }
        )


# ==================================================
# TRACE TAB
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
        # REQUEST
        # ------------------------------------------

        st.write(
            f"### Request: `{latest_trace['request']}`"
        )


        st.write(
            f"### Mode: {latest_trace['mode']}"
        )


        st.divider()


        # ------------------------------------------
        # PIPELINE STAGES
        # ------------------------------------------

        st.subheader("Pipeline")

        for stage in latest_trace["stages"]:

            st.write(f"➡️ {stage}")


        st.divider()


        # ------------------------------------------
        # RAG RESULTS
        # ------------------------------------------

        st.subheader("📚 Retrieved Documents")

        if latest_trace["rag_results"]:

            for result in latest_trace["rag_results"]:

                st.write(
                    f"📄 **{result['document']}** "
                    f"— Similarity Score: `{result['score']}`"
                )

        else:

            st.info(
                "No documents were retrieved."
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

**Status:** 🟡 Not Connected Yet

Will analyze retrieved context and orchestrate the workflow.
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