"""
VulNet FinTech AI Agent Security Lab - Login Page.

Two-step sign-in (password, then MFA) backed by the shared AuthenticationService.
In the lab environment the page also lists the synthetic demo accounts so they can be
picked with one click; hardened environments show neither the accounts nor the MFA code.
"""

import streamlit as st

from auth.models import AuthError
from security import settings

# Synthetic lab credentials (also documented in docs/demo-guide.md). Lab environment only.
DEMO_ACCOUNTS = [
    {"username": "alex_morgan", "password": "Cust001Secure!2026", "name": "Alex Morgan",
     "role": "Customer", "detail": "CUST-001 · ACC-1001, ACC-1002", "icon": "👤"},
    {"username": "jordan_lee", "password": "Cust002Secure!2026", "name": "Jordan Lee",
     "role": "Customer", "detail": "CUST-002 · ACC-2001", "icon": "👤"},
    {"username": "riley_taylor", "password": "Fraud001Secure!2026", "name": "Riley Taylor",
     "role": "Fraud Analyst", "detail": "FRAUD-001", "icon": "🕵️"},
    {"username": "sam_casey", "password": "Support001Secure!2026", "name": "Sam Casey",
     "role": "Support", "detail": "SUPPORT-001", "icon": "🎧"},
    {"username": "morgan_vance", "password": "Admin001Secure!2026", "name": "Morgan Vance",
     "role": "Admin", "detail": "ADMIN-001", "icon": "🛠️"},
]


def is_authenticated(auth_service) -> bool:
    sid = st.session_state.get("active_session_id")
    return bool(sid and auth_service.get_session(sid))


def _fill(account: dict) -> None:
    st.session_state.login_username = account["username"]
    st.session_state.login_password = account["password"]
    st.session_state.login_challenge = None
    st.session_state.login_error = None


def _cancel_mfa() -> None:
    st.session_state.login_challenge = None
    st.session_state.login_error = None


def render_login_page(auth_service) -> None:
    """Render the sign-in screen. Sets st.session_state.active_session_id on success."""
    st.session_state.setdefault("login_challenge", None)
    st.session_state.setdefault("login_error", None)
    st.session_state.setdefault("login_username", "")
    st.session_state.setdefault("login_password", "")

    st.markdown(
        """
        <div style="text-align:center; padding: 8px 0 18px 0;">
            <div style="font-size:40px;">💳</div>
            <div style="font-size:26px; font-weight:700;">VulNet FinTech</div>
            <div style="color:#9CA3AF; font-size:13px;">AI Agent Security Lab · Secure sign-in</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    show_demo = settings.is_lab()
    left, right = st.columns([1, 1.15] if show_demo else [1], gap="large")

    with left:
        st.subheader("Sign in")
        challenge = st.session_state.login_challenge

        if challenge is None:
            with st.form("login_form"):
                st.text_input("Username", key="login_username")
                st.text_input("Password", type="password", key="login_password")
                submitted = st.form_submit_button("Continue", use_container_width=True, type="primary")
            if submitted:
                try:
                    info = auth_service.login(st.session_state.login_username, st.session_state.login_password)
                    st.session_state.login_challenge = info
                    st.session_state.login_error = None
                    st.rerun()
                except AuthError as exc:
                    st.session_state.login_error = str(exc)
        else:
            st.info(f"Password accepted for **{challenge['user_id']}**. Enter the 6-digit MFA code.")
            if challenge.get("mfa_code"):
                st.caption(f"🧪 Lab mode: no SMS/email channel, your code is **{challenge['mfa_code']}**")
            with st.form("mfa_form"):
                code = st.text_input("MFA code", max_chars=6)
                verify = st.form_submit_button("Verify & sign in", use_container_width=True, type="primary")
            st.button("← Use a different account", on_click=_cancel_mfa)
            if verify:
                try:
                    sess = auth_service.verify_mfa(challenge["challenge_id"], code)
                    st.session_state.active_session_id = sess.session_id
                    for key in ("login_challenge", "login_error", "login_password"):
                        st.session_state.pop(key, None)
                    st.session_state.messages = []
                    st.session_state.trace = []
                    st.rerun()
                except AuthError as exc:
                    st.session_state.login_error = str(exc)

        if st.session_state.login_error:
            st.error(st.session_state.login_error)

    if show_demo:
        with right:
            st.subheader("Demo accounts")
            st.caption("Synthetic lab users. Pick one to pre-fill the form, then continue.")
            for acct in DEMO_ACCOUNTS:
                c1, c2 = st.columns([3, 1])
                with c1:
                    st.markdown(
                        f"**{acct['icon']} {acct['name']}** · {acct['role']}  \n"
                        f"<span style='color:#9CA3AF;font-size:12px;'>`{acct['username']}` · {acct['detail']}</span>",
                        unsafe_allow_html=True,
                    )
                with c2:
                    st.button("Use", key=f"use_{acct['username']}", on_click=_fill, args=(acct,),
                              use_container_width=True)
            st.caption("Passwords are pre-filled for the demo only. Set `VULNET_ENV=hardened` to hide this panel.")
