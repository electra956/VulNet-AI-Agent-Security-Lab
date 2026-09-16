"""
VulNet FinTech AI Agent Security Lab - Security & OWASP View Component.
Preserves existing OWASP ASI01-ASI10 scenario simulations, comparative runs,
and FinTech security controls reference.
"""

import streamlit as st
from vulnerabilities.registry import list_scenarios, run_scenario_simulation


def render_security_view() -> None:
    """Renders the OWASP Agentic AI security lab and comparative simulation."""
    st.markdown("### 🛡️ FinTech AI Agent Security Controls & OWASP Lab")
    st.caption("Execute controlled simulations comparing unmitigated Vulnerable execution against hardened Secure defenses across OWASP Top 10 for Agentic AI.")

    sec_tab1, sec_tab2, sec_tab3 = st.tabs([
        "🎯 OWASP Scenarios Lab",
        "⚖️ Human Approvals Queue",
        "ℹ️ System & MCP Tool Registry"
    ])

    with sec_tab1:
        scenarios_list = list_scenarios()
        scenario_options = [f"{s['id']} — {s['name']}" for s in scenarios_list]
        selected_option = st.selectbox("Select Security Scenario", scenario_options)

        selected_id = selected_option.split(" — ")[0]
        selected_meta = next(s for s in scenarios_list if s["id"] == selected_id)

        st.markdown(f"#### 📋 {selected_meta['id']}: {selected_meta['name']}")
        st.markdown(selected_meta["description"])

        col_meta1, col_meta2 = st.columns(2)
        with col_meta1:
            st.info(f"**Attack Preconditions:**\n{selected_meta['preconditions']}")
        with col_meta2:
            st.success(f"**Recommended Mitigations:**\n{selected_meta['mitigation']}")

        st.divider()

        sim_c1, sim_c2, sim_c3 = st.columns(3)
        with sim_c1:
            run_vuln = st.button("🔴 Run Vulnerable Mode", use_container_width=True)
        with sim_c2:
            run_sec = st.button("🟢 Run Secure Mode", use_container_width=True)
        with sim_c3:
            run_comp = st.button("⚖️ Compare Side-by-Side", use_container_width=True)

        if run_vuln:
            st.session_state.scenario_result = {
                "type": "single",
                "vulnerable": run_scenario_simulation(selected_id, mode="vulnerable")
            }
        if run_sec:
            st.session_state.scenario_result = {
                "type": "single",
                "secure": run_scenario_simulation(selected_id, mode="secure")
            }
        if run_comp:
            st.session_state.scenario_result = {
                "type": "compare",
                "vulnerable": run_scenario_simulation(selected_id, mode="vulnerable"),
                "secure": run_scenario_simulation(selected_id, mode="secure")
            }

        # Render Simulation Results
        if st.session_state.scenario_result:
            res_data = st.session_state.scenario_result
            st.markdown("### 📊 Simulation Output & Telemetry")

            if res_data["type"] == "single":
                mode_key = "vulnerable" if "vulnerable" in res_data else "secure"
                sim_out = res_data[mode_key]
                st.markdown(f"**Outcome:** {sim_out.get('outcome', '')}")
                with st.expander("🔍 Telemetry & Events", expanded=True):
                    st.json(sim_out.get("telemetry_events", []))
            elif res_data["type"] == "compare":
                c_vuln, c_sec = st.columns(2)
                with c_vuln:
                    st.markdown("#### 🔴 Vulnerable Mode")
                    st.markdown(res_data["vulnerable"].get("outcome", ""))
                    st.json(res_data["vulnerable"].get("telemetry_events", []))
                with c_sec:
                    st.markdown("#### 🟢 Secure Mode")
                    st.markdown(res_data["secure"].get("outcome", ""))
                    st.json(res_data["secure"].get("telemetry_events", []))

    # =========================================================================
    # TAB 2: HUMAN-IN-THE-LOOP APPROVALS QUEUE
    # =========================================================================
    with sec_tab2:
        from security.approval_engine import get_approval_engine
        approval_engine = get_approval_engine()
        pending_requests = approval_engine.list_pending()

        st.markdown("#### ⚖️ Pending Human Approval Requests")
        st.caption("High-risk simulated financial actions require explicit human authorization before execution.")

        if not pending_requests:
            st.info("ℹ️ No pending human approvals in queue. High-risk transactions (transfers ≥ $10,000, policy changes, card freezes) will trigger authorization requests here.")
        else:
            for req in pending_requests:
                with st.container():
                    st.markdown(
                        f"""
                        <div style="background: #0D1117; border: 1px solid rgba(245,158,11,0.3); border-radius: 10px;
                                    padding: 16px; margin-bottom: 12px;">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                                <span style="font-family: 'JetBrains Mono', monospace; font-weight: 700; color: #F59E0B; font-size: 14px;">
                                    ⚠️ {req.approval_id} — {req.action.upper()}
                                </span>
                                <span style="font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 4px;
                                            background: rgba(245,158,11,0.1); color: #F59E0B; border: 1px solid #F59E0B40;">
                                    RISK: {req.risk}
                                </span>
                            </div>
                            <div style="font-size: 13px; color: #E5E7EB; margin-bottom: 6px;">
                                <strong>User:</strong> {req.user_id} &nbsp;|&nbsp; 
                                <strong>Requested:</strong> {req.timestamp[:19]} &nbsp;|&nbsp;
                                <strong>Expires:</strong> {req.expires_at[:19]}
                            </div>
                            <div style="font-size: 12px; color: #9CA3AF; font-family: monospace; background: rgba(0,0,0,0.3); padding: 8px; border-radius: 6px; margin-bottom: 10px;">
                                {req.parameters}
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                    btn_c1, btn_c2, _ = st.columns([1, 1, 3])
                    with btn_c1:
                        if st.button(f"✅ Approve", key=f"appr_{req.approval_id}", use_container_width=True):
                            res = approval_engine.approve(req.approval_id, approver_id="ADMIN-001", approver_role="ADMIN")
                            st.success(f"Approved request {req.approval_id}!")
                            st.rerun()
                    with btn_c2:
                        if st.button(f"❌ Reject", key=f"rej_{req.approval_id}", use_container_width=True):
                            res = approval_engine.reject(req.approval_id, approver_id="ADMIN-001", approver_role="ADMIN")
                            st.warning(f"Rejected request {req.approval_id}.")
                            st.rerun()

        # Approval History Table
        all_records = approval_engine.list_all()
        if all_records:
            with st.expander("📜 All Approval Records History", expanded=False):
                hist_data = [
                    {
                        "Approval ID": r.approval_id,
                        "Action": r.action,
                        "User": r.user_id,
                        "Risk": r.risk,
                        "Decision": r.decision,
                        "Approver": r.approver_id or "-",
                        "Timestamp": r.timestamp[:19]
                    }
                    for r in all_records
                ]
                st.dataframe(hist_data, use_container_width=True)

    # =========================================================================
    # TAB 3: SYSTEM & MCP TOOL REGISTRY
    # =========================================================================
    with sec_tab3:
        st.markdown("#### 🔒 Safety Isolation Boundaries")
        mc1, mc2, mc3, mc4 = st.columns(4)
        metrics = [
            ("🚫", "Production Access", "DISABLED", "#10B981"),
            ("🌐", "External Network", "AIR-GAPPED", "#10B981"),
            ("🔑", "Real Credentials", "ZERO EXPOSURE", "#10B981"),
            ("🧪", "Simulation Sandbox", "LOCAL ACTIVE", "#00E5FF"),
        ]
        for col, (icon, label, val, color) in zip([mc1, mc2, mc3, mc4], metrics):
            with col:
                st.markdown(
                    f"""
                    <div class="metric-card-simple">
                        <div style="font-size: 22px; margin-bottom: 6px;">{icon}</div>
                        <div class="metric-lbl">{label}</div>
                        <div class="metric-val" style="color: {color};">{val}</div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

        st.divider()

        # MCP Tool Registry
        st.markdown("#### 🔌 Registered FinTech MCP Safe Tools")
        mcp_inst = st.session_state.orchestrator.mcp
        tools = mcp_inst.list_tools()

        risk_colors = {
            "CRITICAL": ("#EF4444", "rgba(239,68,68,0.1)"),
            "HIGH":     ("#F59E0B", "rgba(245,158,11,0.1)"),
            "MEDIUM":   ("#00E5FF", "rgba(0,229,255,0.1)"),
            "LOW":      ("#10B981", "rgba(16,185,129,0.1)"),
        }

        for t in tools:
            meta = mcp_inst.get_tool_info(t) or {}
            risk = meta.get("risk_level", "UNKNOWN").upper()
            perm = meta.get("permission_required", "UNKNOWN").upper()
            desc = meta.get("description", "No description available.")
            color, bg = risk_colors.get(risk, ("#9CA3AF", "rgba(156,163,175,0.1)"))
            st.markdown(
                f"""
                <div style="background: #0D1117; border: 1px solid rgba(255,255,255,0.07); border-radius: 10px;
                            padding: 12px 16px; margin-bottom: 8px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <span style="font-family: 'JetBrains Mono', monospace; font-weight: 700;
                                    color: #00E5FF; font-size: 13px;">🔧 &nbsp;{t}</span>
                        <div style="display: flex; gap: 8px; align-items: center;">
                            <span style="font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 4px;
                                        background: {bg}; color: {color}; border: 1px solid {color}40;">
                                RISK: {risk}
                            </span>
                            <span style="font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 4px;
                                        background: rgba(139,92,246,0.1); color: #A78BFA; border: 1px solid rgba(139,92,246,0.3);">
                                ROLE: {perm}
                            </span>
                        </div>
                    </div>
                    <div style="font-size: 12px; color: #9CA3AF;">{desc}</div>
                </div>
                """,
                unsafe_allow_html=True
            )
