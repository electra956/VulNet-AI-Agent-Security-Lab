"""
VulNet FinTech AI Agent Security Lab - Authentication Models.
Level 2 Step 5: Simulated Customer Authentication.

Defines strongly typed entities for synthetic users, MFA challenges,
authenticated sessions, and domain exceptions.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional


class AuthError(Exception):
    """Base exception for authentication failures."""
    pass


class UserNotFoundError(AuthError):
    """Raised when a requested synthetic user does not exist."""
    pass


class InvalidCredentialsError(AuthError):
    """Raised when authentication credentials fail verification."""
    pass


class MFAVerificationError(AuthError):
    """Raised when an MFA challenge code is invalid or expired."""
    pass


class SessionExpiredError(AuthError):
    """Raised when accessing an expired or terminated session."""
    pass


class UnauthorizedError(AuthError):
    """Raised when an unauthenticated request attempts to access protected resources."""
    pass


@dataclass
class User:
    """
    Synthetic user entity for local lab simulation.
    Never stores plaintext passwords in memory or code.
    """
    user_id: str
    username: str
    full_name: str
    password_hash: str
    salt: str
    role: str
    account_ids: List[str] = field(default_factory=list)
    mfa_enabled: bool = True
    status: str = "ACTIVE"
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Convert to dictionary representation, omitting password hashes by default."""
        data = asdict(self)
        if not include_sensitive:
            data.pop("password_hash", None)
            data.pop("salt", None)
        return data


@dataclass
class MFAChallenge:
    """
    Simulated Multi-Factor Authentication challenge for the lab.
    """
    challenge_id: str
    user_id: str
    code: str
    created_at: str
    expires_at: str
    attempts: int = 0
    max_attempts: int = 3
    verified: bool = False

    def to_dict(self, include_code: bool = False) -> Dict[str, Any]:
        """Convert to dictionary representation, omitting code unless explicitly requested for lab testing."""
        data = asdict(self)
        if not include_code:
            data.pop("code", None)
        return data


@dataclass
class AuthSession:
    """
    Authenticated session entity representing a verified customer or employee.
    Carries user_id, role, session_id, and authorized account_ids.
    """
    session_id: str
    user_id: str
    role: str
    account_ids: List[str]
    authenticated_at: str
    is_active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return asdict(self)
