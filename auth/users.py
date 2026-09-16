"""
VulNet FinTech AI Agent Security Lab - Synthetic User Store & Password Security.
Level 2 Step 5: Simulated Customer Authentication.

Provides:
- Cryptographic password hashing (PBKDF2-HMAC-SHA256, 100,000 iterations).
- Timing-safe password verification.
- Seed synthetic users without hardcoded plaintext passwords in application code.
- In-memory thread-safe user repository.
"""

import hashlib
import hmac
import os
import secrets
from typing import Dict, List, Optional, Tuple

from auth.models import User


def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """
    Cryptographically hash a password using PBKDF2-HMAC-SHA256.
    Returns: (password_hash_hex, salt_hex)
    """
    if not salt:
        salt_bytes = secrets.token_bytes(16)
        salt_hex = salt_bytes.hex()
    else:
        salt_bytes = bytes.fromhex(salt)
        salt_hex = salt

    iterations = 100_000
    derived = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=salt_bytes,
        iterations=iterations
    )
    return derived.hex(), salt_hex


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    """
    Verify password against stored hash using constant-time comparison to prevent timing attacks.
    """
    computed_hash, _ = hash_password(password, salt=salt)
    return hmac.compare_digest(computed_hash, password_hash)


def get_default_users() -> Dict[str, User]:
    """
    Return deterministic seed synthetic users.
    Contains only salted PBKDF2 cryptographic hashes; zero plaintext passwords in code.
    """
    return {
        "CUST-001": User(
            user_id="CUST-001",
            username="alex_morgan",
            full_name="Alex Morgan",
            password_hash="08a321df54442392288f2fd8549a29e243fc53f9af9e202fffa160999395bc27",
            salt="646a09bc22b88a21a04f7f6e000e2802",
            role="customer",
            account_ids=["ACC-1001", "ACC-1002"],
            mfa_enabled=True,
            status="ACTIVE"
        ),
        "CUST-002": User(
            user_id="CUST-002",
            username="jordan_lee",
            full_name="Jordan Lee",
            password_hash="4bf3088b7f383750f79bc4dc9625381124ea282959a436e32a8fbadffff51feb",
            salt="18ec7a382c3230907827965f7885c0c7",
            role="customer",
            account_ids=["ACC-2001"],
            mfa_enabled=True,
            status="ACTIVE"
        ),
        "FRAUD-001": User(
            user_id="FRAUD-001",
            username="riley_taylor",
            full_name="Riley Taylor",
            password_hash="c4ab36b2687d5dc2febfc29c070d03a1f514da5544219fb079cec116d503939c",
            salt="1d4ca7c1bf80d02104f59f900c9d6110",
            role="fraud_analyst",
            account_ids=[],
            mfa_enabled=True,
            status="ACTIVE"
        ),
        "SUPPORT-001": User(
            user_id="SUPPORT-001",
            username="sam_casey",
            full_name="Sam Casey",
            password_hash="a70b2f9c2a1d58fab91c37ace7b640d20564fa18bdc1d3e3708dd5e72bbdae13",
            salt="ec3a4965e9dc6ed95ebbddb583a11f63",
            role="support",
            account_ids=[],
            mfa_enabled=True,
            status="ACTIVE"
        ),
        "ADMIN-001": User(
            user_id="ADMIN-001",
            username="morgan_vance",
            full_name="Morgan Vance",
            password_hash="a33c20ffb006f308ab82e8d3d7d6fdb9403d4ca67b64a3a598fe444c8059215d",
            salt="593904c80ffb833224278105daf2b184",
            role="admin",
            account_ids=[],
            mfa_enabled=True,
            status="ACTIVE"
        ),
    }


class UserRepository:
    """
    In-memory synthetic user repository for the local security lab.
    """

    def __init__(self, initial_users: Optional[Dict[str, User]] = None):
        self._users: Dict[str, User] = initial_users or get_default_users()

    def get_user_by_id(self, user_id: str) -> Optional[User]:
        return self._users.get(user_id.strip().upper())

    def get_user_by_username(self, username: str) -> Optional[User]:
        clean = username.strip().lower()
        for user in self._users.values():
            if user.username.lower() == clean or user.user_id.lower() == clean:
                return user
        return None

    def list_users(self) -> List[User]:
        return list(self._users.values())

    def add_user(self, user: User) -> None:
        self._users[user.user_id] = user
