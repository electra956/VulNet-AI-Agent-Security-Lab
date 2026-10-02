"""Streamlit AppTest coverage for the login gate (no auto-login, demo accounts, MFA step, sign out)."""

from streamlit.testing.v1 import AppTest

from pathlib import Path

APP = str(Path(__file__).resolve().parent.parent / "chatbot" / "app.py")


def _fresh() -> AppTest:
    return AppTest.from_file(APP, default_timeout=60).run()


def _button(at, label):
    return next(b for b in at.button if label in b.label)


def test_dashboard_shows_login_first_with_demo_accounts():
    at = _fresh()
    assert not at.exception
    assert "active_session_id" not in at.session_state
    assert any("Sign in" in s.value for s in at.subheader)
    assert any("Demo accounts" in s.value for s in at.subheader)
    assert len([b for b in at.button if b.label == "Use"]) == 5


def test_full_login_flow_with_mfa_then_sign_out():
    at = _fresh()
    _button(at, "Use").click().run()  # first demo account = alex_morgan
    assert at.session_state.login_username == "alex_morgan"
    next(b for b in at.button if b.label == "Continue").click().run()
    assert at.session_state.login_challenge is not None
    code = at.session_state.login_challenge["mfa_code"]
    at.text_input[0].set_value(code)
    next(b for b in at.button if "Verify" in b.label).click().run()
    assert not at.exception
    assert at.session_state.active_session_id.startswith("SESSION-")
    assert any("CUST-001" in m.value for m in at.markdown)

    next(b for b in at.button if "Sign out" in b.label).click().run()
    assert "active_session_id" not in at.session_state
    assert any("Sign in" in s.value for s in at.subheader)


def test_wrong_password_shows_error():
    at = _fresh()
    at.text_input[0].set_value("alex_morgan")
    at.text_input[1].set_value("wrong")
    next(b for b in at.button if b.label == "Continue").click().run()
    assert any("Invalid username or password" in e.value for e in at.error)
    assert "active_session_id" not in at.session_state


def test_quick_prompts_are_a_single_dropdown_and_work():
    at = _fresh()
    next(b for b in at.button if b.label == "Use").click().run()
    next(b for b in at.button if b.label == "Continue").click().run()
    at.text_input[0].set_value(at.session_state.login_challenge["mfa_code"])
    next(b for b in at.button if "Verify" in b.label).click().run()
    assert not at.exception
    # Every prompt button (banking + ASI01-ASI10) lives inside one popover, not a side panel.
    keys = [b.key for b in at.button if b.key and b.key.startswith("qp_")]
    assert len(keys) == 21
    for asi in range(1, 11):
        assert any(k.startswith(f"qp_asi{asi:02d}") for k in keys), f"missing ASI{asi:02d} prompt"
    next(b for b in at.button if b.key == "qp_fin_bal").click().run()
    assert not at.exception
    assert any("Account Balance" in m.value or "balance" in m.value.lower() for m in at.markdown)


def test_profile_page_shows_account_details_and_signs_out():
    at = _fresh()
    next(b for b in at.button if b.label == "Use").click().run()
    next(b for b in at.button if b.label == "Continue").click().run()
    at.text_input[0].set_value(at.session_state.login_challenge["mfa_code"])
    next(b for b in at.button if "Verify" in b.label).click().run()

    next(r for r in at.radio if r.key == "nav_radio").set_value("👤 Profile")
    at.run()
    assert not at.exception
    page = " ".join(m.value for m in at.markdown)
    assert "alex_morgan" in page and "alex.morgan@vulnet.example" in page
    assert "••••" in page and "Cust001Secure" not in page

    next(b for b in at.button if b.key == "profile_signout").click().run()
    assert "active_session_id" not in at.session_state


def test_pay_page_sends_money_and_updates_balance():
    from fintech.service import reset_shared_fintech_service, get_shared_fintech_service
    reset_shared_fintech_service()
    at = _fresh()
    next(b for b in at.button if b.label == "Use").click().run()
    next(b for b in at.button if b.label == "Continue").click().run()
    at.text_input[0].set_value(at.session_state.login_challenge["mfa_code"])
    next(b for b in at.button if "Verify" in b.label).click().run()
    next(r for r in at.radio if r.key == "nav_radio").set_value("💸 Pay")
    at.run()
    assert not at.exception
    svc = get_shared_fintech_service()
    before = svc.repository.get_account("ACC-2001").balance
    next(n for n in at.number_input if n.key == "pay_amount").set_value(10.0)
    next(b for b in at.button if b.key == "pay_submit").click().run()
    assert not at.exception
    try:
        assert svc.repository.get_account("ACC-2001").balance == before + 10.0
    finally:
        reset_shared_fintech_service()  # don't leak the payment into other tests


def _login_alex():
    at = _fresh()
    next(b for b in at.button if b.label == "Use").click().run()
    next(b for b in at.button if b.label == "Continue").click().run()
    at.text_input[0].set_value(at.session_state.login_challenge["mfa_code"])
    next(b for b in at.button if "Verify" in b.label).click().run()
    return at


def test_each_login_starts_a_new_chat_and_old_chats_are_in_history(tmp_path, monkeypatch):
    from chatbot.sessions import history_store
    monkeypatch.setattr(history_store.ChatHistoryStore, "__init__",
                        lambda self, root=None: setattr(self, "root", tmp_path))
    at = _login_alex()
    assert not at.exception
    next(b for b in at.button if b.key == "qp_fin_bal").click().run()
    first_conv = at.session_state.session_manager.get_session(at.session_state.active_session_id).conversation_id
    assert history_store.ChatHistoryStore().list("CUST-001")[0]["conversation_id"] == first_conv

    # Sign out and back in: the chat area is empty, the old chat is listed in History.
    next(b for b in at.button if "Sign out" in b.label).click().run()
    at2 = _login_alex()
    sess = at2.session_state.session_manager.get_session(at2.session_state.active_session_id)
    assert sess.messages == [] and sess.conversation_id != first_conv
    open_btn = next(b for b in at2.button if b.key == f"hist_open_{first_conv}")
    open_btn.click().run()
    sess = at2.session_state.session_manager.get_session(at2.session_state.active_session_id)
    assert sess.conversation_id == first_conv and any("balance" in str(m.get("content", "")).lower() for m in sess.messages)

    next(b for b in at2.button if "New Chat" in b.label).click().run()
    sess = at2.session_state.session_manager.get_session(at2.session_state.active_session_id)
    assert sess.messages == [] and sess.conversation_id != first_conv
    assert any(b.key == f"hist_open_{first_conv}" for b in at2.button)       # still in history


def test_loading_overlay_is_removed_once_the_dashboard_is_ready():
    at = _login_alex()
    assert not at.exception and at.session_state.app_ready is True
    assert not any("vulnet-loading" in m.value for m in at.markdown)      # overlay gone, dashboard visible
    assert any("CUST-001" in m.value for m in at.markdown)
    from chatbot.components.login import loading_overlay_html
    html = loading_overlay_html()
    assert "position: fixed" in html and "justify-content: center" in html and "align-items: center" in html
