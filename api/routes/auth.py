"""
VulNet FinTech AI Agent Security Lab - Authentication Route.
Level 2 Step 5: Simulated Customer Authentication.

Routes:
- POST /auth/login
- POST /auth/mfa/verify
- POST /auth/logout
- GET /auth/session/{session_id}
"""

import logging
from fastapi import APIRouter, HTTPException, Path, status

from api.schemas import (
    LoginRequest,
    LoginResponse,
    MFAVerifyRequest,
    MFAVerifyResponse,
    LogoutRequest,
    LogoutResponse,
    SessionResponse,
)
from auth.authentication import get_auth_service
from auth.models import (
    InvalidCredentialsError,
    MFAVerificationError,
    UnauthorizedError,
    UserNotFoundError,
)

logger = logging.getLogger("vulnet.api.auth")
router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=LoginResponse)
def login(request: LoginRequest) -> LoginResponse:
    """
    Authenticate username & password, initiating an MFA challenge.
    Does not issue an active session until MFA code is verified.
    """
    auth_service = get_auth_service()
    try:
        res = auth_service.login(request.username, request.password)
        return LoginResponse(
            status=res["status"],
            challenge_id=res["challenge_id"],
            user_id=res["user_id"],
            role=res["role"],
            expires_at=res["expires_at"],
            mfa_code=res.get("mfa_code")
        )
    except InvalidCredentialsError as exc:
        logger.warning("Failed login attempt for '%s': %s", request.username, str(exc))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc)
        )
    except Exception as exc:
        logger.error("Unexpected error in /auth/login: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication failed due to an internal error."
        )


@router.post("/mfa/verify", response_model=MFAVerifyResponse)
def verify_mfa(request: MFAVerifyRequest) -> MFAVerifyResponse:
    """
    Verify 6-digit MFA challenge code and issue active authenticated session.
    """
    auth_service = get_auth_service()
    try:
        session = auth_service.verify_mfa(request.challenge_id, request.code)
        return MFAVerifyResponse(
            status="authenticated",
            session_id=session.session_id,
            user_id=session.user_id,
            role=session.role,
            account_ids=session.account_ids,
            authenticated_at=session.authenticated_at
        )
    except MFAVerificationError as exc:
        logger.warning("MFA verification failure for challenge '%s': %s", request.challenge_id, str(exc))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc)
        )
    except UserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc)
        )
    except Exception as exc:
        logger.error("Unexpected error in /auth/mfa/verify: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA verification failed due to an internal error."
        )


@router.post("/logout", response_model=LogoutResponse)
def logout(request: LogoutRequest) -> LogoutResponse:
    """
    Invalidate active session and revoke subsequent API authorization.
    """
    auth_service = get_auth_service()
    auth_service.logout(request.session_id)
    return LogoutResponse(
        status="logged_out",
        session_id=request.session_id
    )


@router.get("/session/{session_id}", response_model=SessionResponse)
def get_session_info(
    session_id: str = Path(..., min_length=1, max_length=100, description="Session ID to inspect")
) -> SessionResponse:
    """
    Inspect active session status and associated customer authorizations.
    """
    auth_service = get_auth_service()
    try:
        session = auth_service.authenticate_request(session_id)
        return SessionResponse(
            session_id=session.session_id,
            user_id=session.user_id,
            role=session.role,
            account_ids=session.account_ids,
            is_active=session.is_active,
            authenticated_at=session.authenticated_at
        )
    except UnauthorizedError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc)
        )
