"""Tests for the real-world hardening controls: mode policy, MFA exposure, lockout, session TTL, CORS."""

from datetime import datetime, timedelta

from fastapi.testclient import TestClient

from api.main import app
from auth.authentication import AuthenticationService, get_auth_service

client = TestClient(app)
ALEX = ("alex_morgan", "Cust001Secure!2026")


def _session(username="alex_morgan", password="Cust001Secure!2026") -> str:
    login = client.post("/auth/login", json={"username": username, "password": password}).json()
    return client.post(
        "/auth/mfa/verify", json={"challenge_id": login["challenge_id"], "code": login["mfa_code"]}
    ).json()["session_id"]


def test_vulnerable_mode_rejected_when_hardened(monkeypatch):
    sid = _session()
    monkeypatch.setenv("VULNET_ENV", "hardened")
    res = client.post("/chat", json={"session_id": sid, "message": "Hello", "mode": "vulnerable"})
    assert res.status_code == 403


def test_vulnerable_mode_allowed_in_lab():
    sid = _session()
    res = client.post("/chat", json={"session_id": sid, "message": "Hello", "mode": "vulnerable"})
    assert res.status_code == 200


def test_mfa_code_hidden_when_hardened(monkeypatch):
    monkeypatch.setenv("VULNET_ENV", "hardened")
    res = client.post("/auth/login", json={"username": ALEX[0], "password": ALEX[1]})
    assert res.status_code == 200
    assert res.json().get("mfa_code") is None


def test_session_ids_are_random():
    assert _session() != _session()


def test_login_lockout_after_repeated_failures(monkeypatch):
    monkeypatch.setenv("VULNET_MAX_FAILED_LOGINS", "3")
    svc = AuthenticationService()
    for _ in range(3):
        try:
            svc.login("jordan_lee", "wrong-password")
        except Exception:
            pass
    from auth.models import AccountLockedError
    import pytest
    with pytest.raises(AccountLockedError):
        svc.login("jordan_lee", "Cust002Secure!2026")


def test_lockout_returns_429(monkeypatch):
    monkeypatch.setenv("VULNET_MAX_FAILED_LOGINS", "2")
    for _ in range(2):
        client.post("/auth/login", json={"username": "riley_taylor", "password": "bad"})
    res = client.post("/auth/login", json={"username": "riley_taylor", "password": "bad"})
    assert res.status_code == 429
    get_auth_service()._failed_logins.clear()


def test_session_expires_after_ttl(monkeypatch):
    sid = _session()
    auth = get_auth_service()
    auth._active_sessions[sid].authenticated_at = (datetime.now() - timedelta(hours=2)).isoformat()
    res = client.post("/chat", json={"session_id": sid, "message": "Hello"})
    assert res.status_code == 401


def test_cors_not_wildcard_and_security_headers():
    res = client.get("/health", headers={"Origin": "http://evil.example"})
    assert res.headers.get("access-control-allow-origin") != "*"
    assert "access-control-allow-origin" not in res.headers
    assert res.headers["X-Content-Type-Options"] == "nosniff"
    assert res.headers["X-Frame-Options"] == "DENY"
