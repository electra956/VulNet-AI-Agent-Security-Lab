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
    # The 12 prompt buttons live inside one popover, not a side panel.
    keys = [b.key for b in at.button if b.key and b.key.startswith("qp_")]
    assert len(keys) == 12
    next(b for b in at.button if b.key == "qp_fin_bal").click().run()
    assert not at.exception
    assert any("Account Balance" in m.value or "balance" in m.value.lower() for m in at.markdown)
