"""
VulNet FinTech AI Agent Security Lab - Security & OWASP View Component.
Preserves existing OWASP ASI01-ASI10 scenario simulations, comparative runs,
and FinTech security controls reference.
"""

import streamlit as st
from vulnerabilities.registry import list_scenarios, run_scenario_simulation
from observability.audit import get_audit_logger
from security.approval_engine import get_approval_engine


def render_security_view() -> None:
    """Renders the OWASP Agentic AI security lab, KPI metrics, and approvals."""
    st.markdown("### 🛡️ FinTech AI Agent Security Dashboard & OWASP Lab")
    st.caption("Live security posture, automated threat interception metrics, ASI event telemetry, and controlled OWASP simulations.")

    # Compute real-time metrics strictly from local state (NO fabricated statistics)
    traces = st.session_state.get("trace", [])
    total_requests = len(traces)
    blocked_requests = sum(1 for t in traces if t.get("status") == "blocked" or t.get("decision") == "BLOCK")

    sec_events = st.session_state.orchestrator.security.get_events()
    total_sec_events = len(sec_events)

    audit_records = get_audit_logger().get_records(limit=500)
    tool_calls = sum(1 for a in audit_records if a.tool and a.tool != "None")
    high_risk_actions = sum(1 for a in audit_records if a.risk in ("HIGH", "CRITICAL")) + sum(1 for e in sec_events if e.get("severity") in ("CRITICAL", "BLOCKED"))

    approval_engine = get_approval_engine()
    pending_approvals = len(approval_engine.list_pending())

    # =========================================================================
    # 6 MANDATORY KPI METRIC CARDS (STRICTLY ACTUAL LOCAL SYSTEM VALUES)
    # =========================================================================
    r1c1, r1c2, r1c3 = st.columns(3)
    with r1c1:
        st.markdown(
            f"""
            <div class="soc-summary-card">
                <div class="metric-lbl">📊 Total Requests</div>
                <div class="metric-val" style="color: #00E5FF;">{total_requests} Requests</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with r1c2:
        st.markdown(
            f"""
            <div class="soc-summary-card">
                <div class="metric-lbl">🛡️ Blocked Requests</div>
                <div class="metric-val" style="color: #EF4444;">{blocked_requests} Blocked</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with r1c3:
        st.markdown(
            f"""
            <div class="soc-summary-card">
                <div class="metric-lbl">🚨 Security Events</div>
                <div class="metric-val" style="color: #A78BFA;">{total_sec_events} Logged</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    r2c1, r2c2, r2c3 = st.columns(3)
    with r2c1:
        st.markdown(
            f"""
            <div class="soc-summary-card">
                <div class="metric-lbl">🔧 Tool Calls</div>
                <div class="metric-val" style="color: #34D399;">{tool_calls} Executed</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with r2c2:
        st.markdown(
            f"""
            <div class="soc-summary-card">
                <div class="metric-lbl">⚡ High-Risk Actions</div>
                <div class="metric-val" style="color: #F59E0B;">{high_risk_actions} Actions</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with r2c3:
        st.markdown(
            f"""
            <div class="soc-summary-card">
                <div class="metric-lbl">⚖️ Pending Approvals</div>
                <div class="metric-val" style="color: {'#EF4444' if pending_approvals > 0 else '#10B981'};">{pending_approvals} Pending</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # Filter real security events for OWASP categories: ASI01, ASI02, ASI03, ASI06, ASI09
    asi_categories = ["ASI01", "ASI02", "ASI03", "ASI06", "ASI09"]
    categorized_events: dict = {cat: [] for cat in asi_categories}

    for ev in sec_events:
        scen = str(ev.get("scenario") or "")
        typ = str(ev.get("event_type") or "")
        msg = str(ev.get("message") or "")
        for cat in asi_categories:
            if cat in scen or cat in typ or cat in msg or cat in str(ev.get("metadata", {})):
                categorized_events[cat].append(ev)

    # Sub-tabs within Security Dashboard
    sec_tab1, sec_tab2, sec_tab3, sec_tab4 = st.tabs([
        "🚨 Recent Security Events (ASI01-ASI09)",
        "🎯 OWASP Scenarios Lab",
        "⚖️ Human Approvals Queue",
        "ℹ️ System & MCP Tool Registry"
    ])

    with sec_tab1:
        st.markdown("#### 🚨 Recent Real-System Security Events")
        st.caption("Live events categorized by OWASP Top 10 for Agentic AI. Only real events generated by this system are shown.")

        asi_tabs = st.tabs([
            f"ASI01 ({len(categorized_events['ASI01'])})",
            f"ASI02 ({len(categorized_events['ASI02'])})",
            f"ASI03 ({len(categorized_events['ASI03'])})",
            f"ASI06 ({len(categorized_events['ASI06'])})",
            f"ASI09 ({len(categorized_events['ASI09'])})"
        ])

        titles = {
            "ASI01": "ASI01 - Agent Goal Hijack / Prompt Injection",
            "ASI02": "ASI02 - Tool Misuse & Parameter Tampering",
            "ASI03": "ASI03 - Identity & Privilege Abuse / Cross-Customer Access",
            "ASI06": "ASI06 - Memory & Context Poisoning",
            "ASI09": "ASI09 - Overreliance & Financial Policy Violations"
        }

        for idx, cat in enumerate(asi_categories):
            with asi_tabs[idx]:
                st.markdown(f"**{titles[cat]}**")
                ev_list = categorized_events[cat]
                if not ev_list:
                    st.info(f"No {cat} events recorded yet in this local session. Trigger this scenario in the **🎯 OWASP Scenarios Lab** tab or **💬 Chat** to generate real telemetry.")
                else:
                    for ev in reversed(ev_list[-15:]):
                        sev = ev.get("severity", "INFO")
                        sev_color = "#EF4444" if sev in ("CRITICAL", "BLOCKED") else ("#F59E0B" if sev in ("HIGH", "WARNING") else "#10B981")
                        ts = ev.get("timestamp", "").replace("T", " ")[:19]
                        req_id = ev.get("metadata", {}).get("request_id", "")
                        req_badge = f"<code>[{req_id}]</code> &bull; " if req_id else ""

                        st.markdown(
                            f"""
                            <div style="background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.06); border-left: 3px solid {sev_color}; padding: 8px 12px; border-radius: 4px; margin-bottom: 6px;">
                                <div style="display: flex; justify-content: space-between; font-size: 11px; margin-bottom: 2px;">
                                    <span style="color: {sev_color}; font-weight: 700;">[{sev}] {ev.get('event_type', 'EVENT')}</span>
                                    <span style="color: #9CA3AF;">{ts}</span>
                                </div>
                                <div style="font-size: 12px; color: #ECECF1;">
                                    {req_badge}{ev.get('message', '')}
                                </div>
                            </div>
                            """,
                            unsafe_allow_html=True
                        )


    with sec_tab2:
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
                st.markdown(f"**Target Attack Input:**")
                st.code(sim_out.get("attack_input", selected_meta.get("default_input", "")), language="text")
                st.markdown(f"**Outcome:** {sim_out.get('outcome', '')}")

                chk = sim_out.get("checklist")
                if chk:
                    st.markdown("**📋 11-Stage Pipeline Trace Checklist:**")
                    st.code(chk, language="text")

                with st.expander("🔍 Telemetry & Events", expanded=True):
                    st.json(sim_out.get("telemetry_events", []))
            elif res_data["type"] == "compare":
                st.markdown(f"**Target Attack Input:**")
                st.code(res_data["secure"].get("attack_input", ""), language="text")

                c_vuln, c_sec = st.columns(2)
                with c_vuln:
                    st.markdown("#### 🔴 Vulnerable Mode")
                    st.markdown(res_data["vulnerable"].get("outcome", ""))
                    chk_v = res_data["vulnerable"].get("checklist")
                    if chk_v:
                        st.markdown("**Pipeline Trace:**")
                        st.code(chk_v, language="text")
                    with st.expander("🔍 Telemetry Events (Vulnerable)", expanded=False):
                        st.json(res_data["vulnerable"].get("telemetry_events", []))
                with c_sec:
                    st.markdown("#### 🟢 Secure Mode")
                    st.markdown(res_data["secure"].get("outcome", ""))
                    chk_s = res_data["secure"].get("checklist")
                    if chk_s:
                        st.markdown("**Pipeline Trace:**")
                        st.code(chk_s, language="text")
                    with st.expander("🔍 Telemetry Events (Secure)", expanded=False):
                        st.json(res_data["secure"].get("telemetry_events", []))

    # =========================================================================
    # TAB 3: HUMAN-IN-THE-LOOP APPROVALS QUEUE
    with sec_tab3:
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
    # TAB 4: SYSTEM & MCP TOOL REGISTRY
    # =========================================================================
    with sec_tab4:
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
