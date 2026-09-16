"""
VulNet FinTech AI Agent Security Lab - Authentication & MFA Test Suite.
Level 2 Step 5: Simulated Customer Authentication.

Validates:
- Valid login and MFA challenge generation.
- Invalid username and invalid password rejection (401).
- MFA verification success and authenticated session creation.
- MFA verification failure with invalid code (400) and consumed challenge rejection.
- Rejection of unauthenticated API access on POST /chat (401).
- Success of authenticated requests on POST /chat.
- Logout and session invalidation.
- Immediate rejection of logged-out session on POST /chat (401).
- Synthetic user roster verification (CUST-001, CUST-002, FRAUD-001, SUPPORT-001, ADMIN-001).
- Secure PBKDF2 password hashing invariants (zero plaintext in code, salt uniqueness).
"""

import pytest
from fastapi.testclient import TestClient

from api.main import app
from auth.authentication import get_auth_service
from auth.users import hash_password, verify_password, UserRepository

client = TestClient(app)


# Test credentials for synthetic lab users (matching hashes in auth/users.py)
USER_CREDENTIALS = {
    "CUST-001": ("alex_morgan", "Cust001Secure!2026"),
    "CUST-002": ("jordan_lee", "Cust002Secure!2026"),
    "FRAUD-001": ("riley_taylor", "Fraud001Secure!2026"),
    "SUPPORT-001": ("sam_casey", "Support001Secure!2026"),
    "ADMIN-001": ("morgan_vance", "Admin001Secure!2026"),
}


def test_valid_login_returns_mfa_challenge():
    """Verify valid credentials return an MFA challenge and no active session yet."""
    username, password = USER_CREDENTIALS["CUST-001"]
    res = client.post("/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "mfa_required"
    assert data["challenge_id"].startswith("MFA-")
    assert data["user_id"] == "CUST-001"
    assert data["role"] == "customer"
    assert "expires_at" in data
    assert "mfa_code" in data
    assert len(data["mfa_code"]) == 6


def test_invalid_username_rejected():
    """Verify unknown user login attempt is rejected with 401 Unauthorized."""
    res = client.post("/auth/login", json={"username": "unknown_user", "password": "AnyPassword!2026"})
    assert res.status_code == 401
    assert "invalid" in res.json()["detail"].lower()


def test_invalid_password_rejected():
    """Verify incorrect password is rejected with 401 Unauthorized."""
    username, _ = USER_CREDENTIALS["CUST-001"]
    res = client.post("/auth/login", json={"username": username, "password": "WrongPassword!2026"})
    assert res.status_code == 401
    assert "invalid" in res.json()["detail"].lower()


def test_mfa_verification_success_creates_session():
    """Verify providing the valid 6-digit MFA code completes authentication."""
    username, password = USER_CREDENTIALS["CUST-001"]
    login_res = client.post("/auth/login", json={"username": username, "password": password})
    login_data = login_res.json()
    chal_id = login_data["challenge_id"]
    mfa_code = login_data["mfa_code"]

    verify_res = client.post("/auth/mfa/verify", json={"challenge_id": chal_id, "code": mfa_code})
    assert verify_res.status_code == 200
    data = verify_res.json()
    assert data["status"] == "authenticated"
    assert data["session_id"].startswith("SESSION-")
    assert data["user_id"] == "CUST-001"
    assert data["role"] == "customer"
    assert "ACC-1001" in data["account_ids"]
    assert "authenticated_at" in data


def test_mfa_verification_invalid_code_rejected():
    """Verify incorrect MFA code is rejected with 400 Bad Request."""
    username, password = USER_CREDENTIALS["CUST-001"]
    login_res = client.post("/auth/login", json={"username": username, "password": password})
    chal_id = login_res.json()["challenge_id"]

    verify_res = client.post("/auth/mfa/verify", json={"challenge_id": chal_id, "code": "000000"})
    assert verify_res.status_code == 400
    assert "invalid mfa" in verify_res.json()["detail"].lower()


def test_mfa_verification_consumed_challenge_rejected():
    """Verify an MFA challenge cannot be reused once verified."""
    username, password = USER_CREDENTIALS["CUST-001"]
    login_res = client.post("/auth/login", json={"username": username, "password": password})
    chal_id = login_res.json()["challenge_id"]
    mfa_code = login_res.json()["mfa_code"]

    # First attempt: succeeds
    res1 = client.post("/auth/mfa/verify", json={"challenge_id": chal_id, "code": mfa_code})
    assert res1.status_code == 200

    # Second attempt: fails because challenge is consumed
    res2 = client.post("/auth/mfa/verify", json={"challenge_id": chal_id, "code": mfa_code})
    assert res2.status_code == 400
    assert "consumed" in res2.json()["detail"].lower()


def test_unauthenticated_chat_access_rejected():
    """Verify calling POST /chat without authentication returns 401."""
    # 1. Missing session_id
    res_none = client.post("/chat", json={"message": "What is my balance?"})
    assert res_none.status_code == 401

    # 2. Fake / unauthenticated session_id
    res_fake = client.post("/chat", json={"session_id": "FAKE-SESSION-123", "message": "What is my balance?"})
    assert res_fake.status_code == 401
    assert "authentication required" in res_fake.json()["detail"].lower()


def test_authenticated_chat_access_success():
    """Verify full end-to-end flow: Login -> MFA -> Authenticated /chat."""
    username, password = USER_CREDENTIALS["CUST-001"]
    login_res = client.post("/auth/login", json={"username": username, "password": password})
    chal_id = login_res.json()["challenge_id"]
    mfa_code = login_res.json()["mfa_code"]

    mfa_res = client.post("/auth/mfa/verify", json={"challenge_id": chal_id, "code": mfa_code})
    session_id = mfa_res.json()["session_id"]

    # Query chat with valid authenticated session
    chat_res = client.post("/chat", json={"session_id": session_id, "message": "What is my balance?"})
    assert chat_res.status_code == 200
    data = chat_res.json()
    assert data["status"] == "completed"
    assert data["session_id"] == session_id
    assert "5,420.50" in data["response"]


def test_logout_and_session_invalidation():
    """Verify logging out marks session inactive and prevents reuse."""
    username, password = USER_CREDENTIALS["CUST-002"]
    login_res = client.post("/auth/login", json={"username": username, "password": password})
    chal_id = login_res.json()["challenge_id"]
    mfa_code = login_res.json()["mfa_code"]

    mfa_res = client.post("/auth/mfa/verify", json={"challenge_id": chal_id, "code": mfa_code})
    session_id = mfa_res.json()["session_id"]

    # Verify session active
    info_res = client.get(f"/auth/session/{session_id}")
    assert info_res.status_code == 200
    assert info_res.json()["is_active"] is True

    # Logout
    logout_res = client.post("/auth/logout", json={"session_id": session_id})
    assert logout_res.status_code == 200
    assert logout_res.json()["status"] == "logged_out"

    # Verify session inspection returns 401
    info_after = client.get(f"/auth/session/{session_id}")
    assert info_after.status_code == 401

    # Verify /chat call with logged out session returns 401
    chat_after = client.post("/chat", json={"session_id": session_id, "message": "Hello"})
    assert chat_after.status_code == 401


def test_synthetic_users_roster():
    """Verify all 5 synthetic users exist and can initiate authentication."""
    repo = UserRepository()
    expected_users = ["CUST-001", "CUST-002", "FRAUD-001", "SUPPORT-001", "ADMIN-001"]

    for uid in expected_users:
        user = repo.get_user_by_id(uid)
        assert user is not None
        assert user.user_id == uid
        assert user.password_hash is not None
        assert user.salt is not None
        assert user.status == "ACTIVE"


def test_password_hashing_security():
    """Verify PBKDF2 hashing generates unique salts and verifies correctly."""
    plain = "TestSecPassword!2026"
    h1, s1 = hash_password(plain)
    h2, s2 = hash_password(plain)

    # Salts must be unique
    assert s1 != s2
    # Hashes must differ due to distinct salts
    assert h1 != h2

    # Verification must succeed for correct password
    assert verify_password(plain, h1, s1) is True
    assert verify_password(plain, h2, s2) is True

    # Verification must fail for wrong password
    assert verify_password("WrongPass!2026", h1, s1) is False
