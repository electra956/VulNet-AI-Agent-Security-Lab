"""
VulNet FinTech AI Agent Security Lab - Authentication Service.
Level 2 Step 5: Simulated Customer Authentication.

Coordinates:
- Username & Password verification (PBKDF2).
- MFA challenge initiation & verification.
- Authenticated session lifecycle (login, verify_mfa, logout, authenticate_request).
- Integration with SessionManager and SessionContext.
"""

from datetime import datetime
import logging
from typing import Any, Dict, Optional

from auth.models import (
    AuthSession,
    InvalidCredentialsError,
    MFAVerificationError,
    SessionExpiredError,
    UnauthorizedError,
    UserNotFoundError,
)
from auth.mfa import MFAService
from auth.users import UserRepository, verify_password
from chatbot.sessions.session_manager import SessionManager, CustomerContext, get_shared_session_manager

logger = logging.getLogger("vulnet.auth")


class AuthenticationService:
    """
    Core authentication provider for the local FinTech security lab.
    """

    def __init__(
        self,
        user_repo: Optional[UserRepository] = None,
        mfa_service: Optional[MFAService] = None,
        session_manager: Optional[SessionManager] = None
    ):
        self.user_repo = user_repo or UserRepository()
        self.mfa_service = mfa_service or MFAService()
        self.session_manager = session_manager or get_shared_session_manager()
        self._active_sessions: Dict[str, AuthSession] = {}

    def login(self, username: str, password: str) -> Dict[str, Any]:
        """
        Step 1 & 2 of authentication:
        Validates username and hashed password, then generates an MFA challenge.
        Does NOT return an authenticated session until MFA is verified.
        """
        if not username or not username.strip():
            raise InvalidCredentialsError("Username cannot be empty.")

        if not password:
            raise InvalidCredentialsError("Password cannot be empty.")

        user = self.user_repo.get_user_by_username(username.strip())
        if not user:
            # Mask whether username or password was incorrect
            raise InvalidCredentialsError("Invalid username or password.")

        if user.status != "ACTIVE":
            raise InvalidCredentialsError("User account is disabled or suspended.")

        if not verify_password(password, user.password_hash, user.salt):
            raise InvalidCredentialsError("Invalid username or password.")

        # Credentials valid: Initiate MFA challenge
        challenge = self.mfa_service.create_challenge(user.user_id)
        logger.info("MFA challenge '%s' issued for user '%s'", challenge.challenge_id, user.user_id)

        return {
            "status": "mfa_required",
            "challenge_id": challenge.challenge_id,
            "user_id": user.user_id,
            "role": user.role,
            "expires_at": challenge.expires_at,
            "mfa_code": challenge.code,  # Exposed for local test harness & lab inspection
        }

    def verify_mfa(self, challenge_id: str, code: str) -> AuthSession:
        """
        Step 3 & 4 of authentication:
        Verifies the MFA code and issues a fully authenticated session carrying:
        - user_id
        - role
        - session_id
        - account_ids
        """
        if not challenge_id or not challenge_id.strip():
            raise MFAVerificationError("MFA challenge ID is required.")

        if not code or not code.strip():
            raise MFAVerificationError("MFA verification code is required.")

        challenge = self.mfa_service.get_challenge(challenge_id.strip())
        if not challenge:
            raise MFAVerificationError(f"MFA challenge '{challenge_id}' not found.")

        # Verify challenge code
        self.mfa_service.verify_challenge(challenge_id.strip(), code.strip())

        user = self.user_repo.get_user_by_id(challenge.user_id)
        if not user:
            raise UserNotFoundError(f"User '{challenge.user_id}' associated with challenge not found.")

        # Create session ID and AuthSession
        session_id = self.session_manager.generate_session_id()
        auth_session = AuthSession(
            session_id=session_id,
            user_id=user.user_id,
            role=user.role,
            account_ids=list(user.account_ids),
            authenticated_at=datetime.now().isoformat(),
            is_active=True
        )
        self._active_sessions[session_id] = auth_session

        # Synchronize with SessionManager so downstream agents & components have context
        cust_ctx = CustomerContext(
            customer_id=user.user_id,
            account_id=user.account_ids[0] if user.account_ids else "NO-ACCT",
            account_ids=list(user.account_ids),
            user_role=user.role,
            full_name=user.full_name,
            balance=5420.50 if user.user_id == "CUST-001" else (3100.25 if user.user_id == "CUST-002" else 0.0),
        )
        session_obj = self.session_manager.create_session(
            user_id=user.user_id,
            customer_context=cust_ctx,
            session_id=session_id
        )
        session_obj.metadata["is_authenticated"] = True
        session_obj.metadata["auth_time"] = auth_session.authenticated_at

        logger.info("User '%s' authenticated successfully. Session: '%s'", user.user_id, session_id)
        return auth_session

    def logout(self, session_id: str) -> bool:
        """
        Terminates the authenticated session and invalidates downstream state.
        """
        if not session_id:
            return False

        clean_id = session_id.strip()
        auth_session = self._active_sessions.get(clean_id)
        if not auth_session:
            return False

        auth_session.is_active = False
        self._active_sessions.pop(clean_id, None)

        # Invalidate in SessionManager as well
        sess_obj = self.session_manager.get_session(clean_id)
        if sess_obj:
            sess_obj.metadata["is_authenticated"] = False
            sess_obj.metadata["terminated_at"] = datetime.now().isoformat()

        logger.info("Session '%s' logged out and invalidated.", clean_id)
        return True

    def authenticate_request(self, session_id: Optional[str] = None) -> AuthSession:
        """
        Verifies that the request carries an active, validly authenticated session.
        Raises UnauthorizedError if session is missing, invalid, or expired.
        """
        if not session_id or not session_id.strip():
            raise UnauthorizedError("Authentication required. No session identifier provided.")

        clean_id = session_id.strip()
        session = self._active_sessions.get(clean_id)
        if not session or not session.is_active:
            raise UnauthorizedError(f"Session '{clean_id}' is invalid, unauthenticated, or expired. Please log in.")

        return session

    def get_session(self, session_id: str) -> Optional[AuthSession]:
        """Lookup active session by ID."""
        session = self._active_sessions.get(session_id.strip())
        if session and session.is_active:
            return session
        return None


# Global singleton instance for application use
_default_auth_service = AuthenticationService()


def get_auth_service() -> AuthenticationService:
    return _default_auth_service
