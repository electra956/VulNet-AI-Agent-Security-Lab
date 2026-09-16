"""
VulNet FinTech AI Agent Security Lab - Tools Management & MCP Registry View.
Level 2 Step 16: Security Observability UI.

Provides:
- Inventory of registered simulated fintech tools
- Metadata inspection: name, description, risk level, allowed roles, requires approval, schemas
- Real-time invocation metrics derived strictly from local system state
- Sandbox inspection of tool interfaces
"""

from typing import Any, Dict, List
import streamlit as st

from mcp_server.server import MCPServer
from mcp_server.tools import create_default_registry
from observability.audit import get_audit_logger


def render_tools_view() -> None:
    """Renders the simulated FinTech Tools and MCP Registry dashboard."""
    st.markdown("### 🔌 Simulated FinTech Tools & MCP Tool Gateway")
    st.caption("Secure MCP Tool Registry with role-based access control, deterministic risk tiering, and execution sandboxes.")

    # Initialize registry lookup
    registry = create_default_registry()
    all_tool_names = registry.list_tools()
    audit_records = get_audit_logger().get_records(limit=200)

    # Tool invocation counts from real local audit records
    tool_counts: Dict[str, int] = {}
    for rec in audit_records:
        if rec.tool and rec.tool != "None":
            tool_counts[rec.tool] = tool_counts.get(rec.tool, 0) + 1

    total_registered = len(all_tool_names)
    total_invocations = sum(tool_counts.values())
    high_risk_count = sum(1 for name in all_tool_names if (registry.get(name) and registry.get(name).risk_level in ("HIGH", "CRITICAL")))
    approval_required_count = sum(1 for name in all_tool_names if (registry.get(name) and registry.get(name).requires_approval))

    # Top KPI Metrics (strictly computed from local registry and audit data)
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(
            f"""
            <div class="soc-summary-card">
                <div class="metric-lbl">🔌 Registered Tools</div>
                <div class="metric-val" style="color: #00E5FF;">{total_registered} Tools</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with c2:
        st.markdown(
            f"""
            <div class="soc-summary-card">
                <div class="metric-lbl">⚡ Local Tool Invocations</div>
                <div class="metric-val" style="color: #10B981;">{total_invocations} Recorded</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with c3:
        st.markdown(
            f"""
            <div class="soc-summary-card">
                <div class="metric-lbl">🚨 High/Critical Risk</div>
                <div class="metric-val" style="color: #EF4444;">{high_risk_count} Tools</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with c4:
        st.markdown(
            f"""
            <div class="soc-summary-card">
                <div class="metric-lbl">⚖️ Approval Required</div>
                <div class="metric-val" style="color: #F59E0B;">{approval_required_count} Tools</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # Categories filter
    categories = {
        "ALL": all_tool_names,
        "ACCOUNT": [t for t in all_tool_names if any(k in t for k in ("account", "balance", "profile", "history"))],
        "PAYMENT": [t for t in all_tool_names if any(k in t for k in ("payment", "transfer"))],
        "CARD": [t for t in all_tool_names if "card" in t],
        "FRAUD": [t for t in all_tool_names if any(k in t for k in ("fraud", "risk", "flag"))],
        "KYC": [t for t in all_tool_names if any(k in t for k in ("kyc", "identity"))],
        "SUPPORT": [t for t in all_tool_names if any(k in t for k in ("support", "ticket", "notification"))],
        "SYSTEM / MCP": [t for t in all_tool_names if any(k in t for k in ("security", "audit", "system"))]
    }

    selected_cat = st.radio(
        "Tool Category",
        list(categories.keys()),
        horizontal=True,
        label_visibility="collapsed"
    )

    filtered_tools = categories.get(selected_cat, all_tool_names)
    st.markdown(f"#### 🛠️ Available Tools in `{selected_cat}` ({len(filtered_tools)} tools)")

    for name in filtered_tools:
        meta = registry.get(name)
        if not meta:
            continue

        invocations = tool_counts.get(name, 0)
        risk_color = "#10B981" if meta.risk_level == "LOW" else ("#F59E0B" if meta.risk_level == "MEDIUM" else "#EF4444")
        approval_badge = "⚖️ Human Approval Required" if meta.requires_approval else "⚡ Automated Execution"

        expander_title = f"`{name}` &bull; Risk: {meta.risk_level} &bull; Calls: {invocations}"
        with st.expander(expander_title, expanded=False):
            st.markdown(f"**Description:** {meta.description}")

            m1, m2, m3, m4 = st.columns(4)
            with m1:
                st.markdown(f"**Risk Level:** <span style='color:{risk_color};font-weight:700;'>{meta.risk_level}</span>", unsafe_allow_html=True)
            with m2:
                roles_str = ", ".join(meta.allowed_roles)
                st.markdown(f"**Allowed Roles:** `{roles_str}`")
            with m3:
                st.markdown(f"**Policy:** `{approval_badge}`")
            with m4:
                st.markdown(f"**Session Calls:** `{invocations}`")

            st.markdown("<div style='height: 6px;'></div>", unsafe_allow_html=True)
            c_in, c_out = st.columns(2)
            with c_in:
                st.markdown("**📥 Input Schema:**")
                st.json(meta.input_schema)
            with c_out:
                st.markdown("**📤 Output Schema:**")
                st.json(meta.output_schema)
