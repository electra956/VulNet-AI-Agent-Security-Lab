"""
VulNet FinTech AI Agent Security Lab - Profile View.
Shows the signed-in user's account details (username, email, masked password) and sign-out.
Passwords are never stored or shown in plaintext: only a salted PBKDF2 hash exists.
"""

import streamlit as st
from auth.authentication import get_auth_service
from auth.users import UserRepository


def sign_out() -> None:
    """Invalidate the auth session and clear UI state (keeps the session manager)."""
    get_auth_service().logout(st.session_state.get("active_session_id", ""))
    for key in list(st.session_state.keys()):
        if key not in ("session_manager",):
            del st.session_state[key]
    st.rerun()


def render_profile_view(current_session) -> None:
    auth_session = get_auth_service().get_session(st.session_state.get("active_session_id", ""))
    user = UserRepository().get_user_by_id(auth_session.user_id) if auth_session else None

    st.markdown("### 👤 My Profile")
    st.caption("Your account details for this synthetic lab. Demo data only.")
    if user is None:
        st.warning("Profile unavailable for this session.")
        return

    rows = [
        ("Full name", user.full_name),
        ("Username", user.username),
        ("Email", user.email or "—"),
        ("Password", "••••••••••••"),
        ("User ID", user.user_id),
        ("Role", user.role),
        ("Status", user.status),
        ("MFA", "Enabled" if user.mfa_enabled else "Disabled"),
        ("Linked accounts", ", ".join(user.account_ids) or "—"),
    ]
    html = "".join(
        f'<div style="display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid rgba(255,255,255,0.06);">'
        f'<span style="color:#9CA3AF;">{k}</span><span style="font-weight:600;">{v}</span></div>'
        for k, v in rows
    )
    st.markdown(
        f'<div style="background:#0D1117; border:1px solid rgba(255,255,255,0.08); border-radius:10px; padding:10px 20px; margin-bottom:12px;">{html}</div>',
        unsafe_allow_html=True,
    )
    st.caption("🔒 Passwords are stored only as salted PBKDF2-HMAC-SHA256 hashes, so the real password can't be displayed.")

    if st.button("🚪 Sign out", key="profile_signout", type="primary"):
        sign_out()
