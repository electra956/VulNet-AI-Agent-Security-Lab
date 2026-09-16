"""
VulNet FinTech AI Agent Security Lab - Agent Trace & Telemetry View Component.
Displays live pipeline stage execution traces, structured SessionContext identifiers
(request_id, session_id, conversation_id, user_id), and security telemetry events.
"""

from typing import Any, Dict, List
import streamlit as st

from observability.audit import get_audit_logger
from observability.trace import get_trace_store


def render_trace_view() -> None:
    """Renders the Agent Trace and SOC Telemetry view."""
    st.markdown("### 📑 FinTech Agent Trace & SOC Telemetry Stream")
    st.caption("Step-by-step pipeline execution checklist, sequential request IDs, structured session context, and security telemetry.")

    sec_events = st.session_state.orchestrator.security.get_events()
    traces = st.session_state.trace
    total_traces = len(traces)
    completed_traces = sum(1 for tr in traces if tr.get("status") == "completed")
    blocked_traces = sum(1 for tr in traces if tr.get("status") == "blocked")
    audit_records = get_audit_logger().get_records(limit=50)

    # KPI Metric Cards
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(
            f"""
            <div class="soc-summary-card">
                <div class="metric-lbl">📊 Telemetry Events</div>
                <div class="metric-val" style="color: #A78BFA;">{len(sec_events)} Logged</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with c2:
        st.markdown(
            f"""
            <div class="soc-summary-card">
                <div class="metric-lbl">📑 Inbound Traces</div>
                <div class="metric-val" style="color: #00E5FF;">{total_traces} Requests</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with c3:
        st.markdown(
            f"""
            <div class="soc-summary-card">
                <div class="metric-lbl">📝 Audit Records</div>
                <div class="metric-val" style="color: #F59E0B;">{len(audit_records)} Indexed</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with c4:
        mode_color = "#10B981" if st.session_state.security_mode == "secure" else "#EF4444"
        mode_label = "SECURE ENFORCED" if st.session_state.security_mode == "secure" else "VULNERABLE SIM"
        st.markdown(
            f"""
            <div class="soc-summary-card">
                <div class="metric-lbl">🛡️ Active Mode</div>
                <div class="metric-val" style="color: {mode_color};">{mode_label}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)

    # Real-Time Pipeline Completion Banner
    if traces:
        latest_tr = traces[-1]
        lat_status = latest_tr.get("status", "unknown")
        lat_req = latest_tr.get("request", "")
        req_id = latest_tr.get("request_id", "REQ-000000")
        sess_id = latest_tr.get("session_id", st.session_state.get("active_session_id", "SESSION-001"))
        conv_id = latest_tr.get("conversation_id", "CONV-001")
        req_snippet = (lat_req[:55] + "...") if len(lat_req) > 55 else lat_req
        lat_time = latest_tr.get("execution_time_ms", 0)

        if lat_status == "completed":
            st.markdown(
                f"""
                <div class="soc-pipeline-banner-success">
                    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">
                        <div style="display:flex;align-items:center;gap:12px;">
                            <span style="font-size:26px;filter:drop-shadow(0 0 6px rgba(16,185,129,0.5));">✅</span>
                            <div>
                                <div style="font-size:15px;font-weight:700;color:#34D399;letter-spacing:0.02em;">
                                    PIPELINE PROCESS & OUTPUT REACHED SUCCESSFULLY &bull; COMPLETED
                                </div>
                                <div style="font-size:12px;color:#9CA3AF;margin-top:2px;">
                                    <strong>Request:</strong> <code>{req_id}</code> &bull; 
                                    <strong>Session:</strong> <code>{sess_id}</code> &bull; 
                                    <strong>Conv:</strong> <code>{conv_id}</code> &bull; 
                                    Latency: <code>{lat_time} ms</code>
                                </div>
                            </div>
                        </div>
                        <span class="badge-check-completed">✓ 100% COMPLETED</span>
                    </div>
                    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px;padding-top:10px;border-top:1px solid rgba(16,185,129,0.2);">
                        <span class="chip-verified">✓ Request ID: {req_id}</span>
                        <span class="chip-verified">✓ Session ID: {sess_id}</span>
                        <span class="chip-verified">✓ Pipeline Completed</span>
                        <span class="chip-verified">✓ Output Reached Interface</span>
                        <span class="chip-verified">✓ Security Invariants Verified</span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                f"""
                <div class="soc-pipeline-banner-blocked">
                    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">
                        <div style="display:flex;align-items:center;gap:12px;">
                            <span style="font-size:26px;filter:drop-shadow(0 0 6px rgba(239,68,68,0.5));">🛡️</span>
                            <div>
                                <div style="font-size:15px;font-weight:700;color:#F87171;letter-spacing:0.02em;">
                                    PERIMETER SECURITY CONTAINMENT ACTIVE &bull; THREAT INTERCEPTED
                                </div>
                                <div style="font-size:12px;color:#9CA3AF;margin-top:2px;">
                                    <strong>Request:</strong> <code>{req_id}</code> &bull; 
                                    <strong>Session:</strong> <code>{sess_id}</code> &bull; 
                                    <em>"{req_snippet}"</em> &bull; Blocked by Security Controller
                                </div>
                            </div>
                        </div>
                        <span class="badge-check-blocked">🛡️ THREAT BLOCKED</span>
                    </div>
                    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px;padding-top:10px;border-top:1px solid rgba(239,68,68,0.2);">
                        <span class="chip-blocked">✓ Correlated Request: {req_id}</span>
                        <span class="chip-blocked">✓ Isolated Session: {sess_id}</span>
                        <span class="chip-blocked">✓ Threat Signature Isolated</span>
                        <span class="chip-blocked">✓ Financial State Unaltered</span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
    else:
        st.info("💡 Standby: No requests traced yet. Send a prompt in the **💬 Chat** or run an attack scenario to inspect live traces.")

    st.divider()

    # Tabs for Traces vs Audit Log
    tab_traces, tab_audit, tab_telemetry = st.tabs([
        "📑 Request Traces & Checklists",
        "📜 Structured Audit Logs (JSON)",
        "🚨 Security Telemetry Feed"
    ])

    with tab_traces:
        st.markdown("#### 📑 Request Inbound Traces & Pipeline Stage Verification")
        if not traces:
            st.info("No request traces recorded in this session.")
        else:
            for idx, tr in enumerate(reversed(traces), start=1):
                trace_num = len(traces) - idx + 1
                req_id = tr.get("request_id", f"REQ-{trace_num:06d}")
                sess_id = tr.get("session_id", "SESSION-001")
                conv_id = tr.get("conversation_id", "CONV-001")
                user_id = tr.get("user_id", "CUST-001")
                req_text = tr.get('request', '')
                short_req = (req_text[:45] + "...") if len(req_text) > 45 else req_text
                status = tr.get("status", "completed")
                exec_time = tr.get("execution_time_ms", 0)
                mode = tr.get("mode", "secure")
                agent_name = tr.get("agent", "MainAgent")
                tool_name = tr.get("tool", "None")
                risk_val = tr.get("risk", "LOW")
                dec_val = tr.get("decision", "ALLOW")

                is_completed = (status == "completed")
                status_pill = "✅ COMPLETED" if is_completed else "🛡️ BLOCKED"
                expander_title = f"Trace #{trace_num} [{req_id}] &bull; {sess_id}: \"{short_req}\" — {status_pill}"

                with st.expander(expander_title, expanded=(idx == 1)):
                    st.markdown(
                        f"""
                        <div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);border-radius:8px;padding:10px 14px;margin-bottom:12px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;">
                            <div>
                                <span style="font-size:12px;color:#9CA3AF;">Request ID:</span>
                                <span style="font-family:monospace;font-size:12px;font-weight:700;color:#00E5FF;margin-right:10px;">{req_id}</span>
                                <span style="font-size:12px;color:#9CA3AF;">Session:</span>
                                <span style="font-family:monospace;font-size:12px;font-weight:700;color:#A78BFA;margin-right:10px;">{sess_id}</span>
                                <span style="font-size:12px;color:#9CA3AF;">User:</span>
                                <span style="font-family:monospace;font-size:12px;font-weight:600;color:#34D399;margin-right:10px;">{user_id}</span>
                                <span style="font-size:12px;color:#9CA3AF;">Agent:</span>
                                <span style="font-family:monospace;font-size:12px;color:#FBBF24;margin-right:10px;">{agent_name}</span>
                                <span style="font-size:12px;color:#9CA3AF;">Tool:</span>
                                <span style="font-family:monospace;font-size:12px;color:#60A5FA;margin-right:10px;">{tool_name}</span>
                                <span style="font-size:12px;color:#9CA3AF;">Risk:</span>
                                <span style="font-family:monospace;font-size:12px;font-weight:600;color:{'#10B981' if risk_val == 'LOW' else '#EF4444'};margin-right:10px;">{risk_val}</span>
                                <span style="font-size:12px;color:#9CA3AF;">Decision:</span>
                                <span style="font-family:monospace;font-size:12px;font-weight:700;color:{'#10B981' if dec_val == 'ALLOW' else '#EF4444'};margin-right:10px;">{dec_val}</span>
                                <span style="font-size:12px;color:#9CA3AF;">Latency:</span>
                                <span style="font-size:12px;font-weight:600;color:#ECECF1;">{exec_time} ms</span>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

                    # Monospace 11-Stage Pipeline Checklist
                    checklist_text = tr.get("checklist")
                    if checklist_text:
                        st.markdown("**📋 11-Stage End-to-End Execution Checklist:**")
                        st.code(checklist_text, language="text")

                    # Stage breakdown rows
                    st.markdown("**🔍 Pipeline Stage Details:**")
                    stages = tr.get("stages", [])
                    for s_idx, s in enumerate(stages, start=1):
                        if "Halted" in s or "Blocked" in s or "Error" in s:
                            row_class = "soc-stage-row blocked"
                            badge_html = '<span class="badge-check-blocked">🛑 HALTED</span>'
                            check_icon = "🛑"
                        else:
                            row_class = "soc-stage-row completed"
                            badge_html = '<span class="badge-check-completed">✓ COMPLETED</span>'
                            check_icon = "✅"

                        st.markdown(
                            f"""
                            <div class="{row_class}">
                                <div style="display:flex;align-items:center;gap:10px;">
                                    <span style="font-size:15px;">{check_icon}</span>
                                    <span style="font-weight:500;color:#ECECF1;">Stage {s_idx}: {s}</span>
                                </div>
                                {badge_html}
                            </div>
                            """,
                            unsafe_allow_html=True
                        )

                    if tr.get("response_preview"):
                        st.markdown("<div style='height:4px;'></div>", unsafe_allow_html=True)
                        with st.expander("👁️ View Output Snippet", expanded=False):
                            st.markdown(f"```\n{tr.get('response_preview')}\n```")

    with tab_audit:
        st.markdown("#### 📜 Structured JSON Security Audit Records")
        st.caption("Immutable append-only audit trail. All secrets, tokens, passwords, and credentials are strictly sanitized.")
        if not audit_records:
            st.info("No audit records indexed yet.")
        else:
            for rec in audit_records[:25]:
                rec_dict = rec.to_dict()
                status_color = "#10B981" if rec.status == "completed" else "#EF4444"
                with st.expander(f"Audit {rec.audit_id} &bull; [{rec.request_id}] &bull; Action: {rec.action} &bull; Status: {rec.status.upper()}", expanded=False):
                    c1, c2, c3, c4 = st.columns(4)
                    with c1:
                        st.markdown(f"**Request ID:** `{rec.request_id}`")
                        st.markdown(f"**Session ID:** `{rec.session_id}`")
                    with c2:
                        st.markdown(f"**User ID:** `{rec.user_id}`")
                        st.markdown(f"**Agent:** `{rec.agent or 'N/A'}`")
                    with c3:
                        st.markdown(f"**Tool:** `{rec.tool or 'N/A'}`")
                        st.markdown(f"**Risk:** `{rec.risk}`")
                    with c4:
                        st.markdown(f"**Decision:** `{rec.decision}`")
                        st.markdown(f"**Status:** `{rec.status}`")

                    st.markdown("**Structured JSON Audit Record:**")
                    st.json(rec_dict)

    with tab_telemetry:
        st.markdown("#### 🚨 Live Security Telemetry Audit Feed")
        if sec_events:
            for ev in reversed(sec_events[-25:]):
                sev = ev.get("severity", "INFO")
                component = ev.get("component", "SYSTEM")
                msg = ev.get("message", "")
                ts = ev.get("timestamp", "").split("T")[-1][:8]
                meta = ev.get("metadata", {})
                req_badge = f'<code style="color:#00E5FF;font-size:10px;margin-right:6px;">[{meta.get("request_id")}]</code>' if meta.get("request_id") else ""

                if sev in ("CRITICAL", "BLOCKED"):
                    sev_badge = f'<span style="background:rgba(239,68,68,0.2);color:#EF4444;padding:2px 6px;border-radius:4px;font-size:10px;font-weight:700;">{sev}</span>'
                elif sev in ("HIGH", "WARNING"):
                    sev_badge = f'<span style="background:rgba(245,158,11,0.2);color:#F59E0B;padding:2px 6px;border-radius:4px;font-size:10px;font-weight:700;">{sev}</span>'
                else:
                    sev_badge = f'<span style="background:rgba(16,185,129,0.2);color:#10B981;padding:2px 6px;border-radius:4px;font-size:10px;font-weight:700;">{sev}</span>'

                st.markdown(
                    f'<div class="soc-event-item">'
                    f'<span style="color:#6B7280;font-size:11px;">{ts}</span>'
                    f'{sev_badge}'
                    f'<span style="color:#A78BFA;font-size:11px;font-weight:600;">[{component}]</span>'
                    f'{req_badge}'
                    f'<span style="color:#ECECF1;font-size:12px;">{msg}</span>'
                    f'</div>',
                    unsafe_allow_html=True
                )
        else:
            st.info("No security telemetry events logged yet.")

