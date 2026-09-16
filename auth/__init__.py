"""
VulNet FinTech AI Agent Security Lab - Authentication Subsystem.
Level 2 Step 5: Simulated Customer Authentication.
"""

from auth.models import (
    User,
    MFAChallenge,
    AuthSession,
    AuthError,
    UserNotFoundError,
    InvalidCredentialsError,
    MFAVerificationError,
    SessionExpiredError,
    UnauthorizedError,
)
from auth.users import UserRepository, hash_password, verify_password, get_default_users
from auth.mfa import MFAService
from auth.authentication import AuthenticationService, get_auth_service
from auth.roles import Role, normalize_role
from auth.permissions import (
    Permission,
    ROLE_PERMISSIONS,
    normalize_permission,
    get_permissions_for_role,
)
from auth.authorization import (
    AuthorizationError,
    PermissionDeniedError,
    ResourceAccessDeniedError,
    has_permission,
    authorize_action,
    authorize_resource_access,
)

__all__ = [
    "User",
    "MFAChallenge",
    "AuthSession",
    "AuthError",
    "UserNotFoundError",
    "InvalidCredentialsError",
    "MFAVerificationError",
    "SessionExpiredError",
    "UnauthorizedError",
    "UserRepository",
    "hash_password",
    "verify_password",
    "get_default_users",
    "MFAService",
    "AuthenticationService",
    "get_auth_service",
    "Role",
    "normalize_role",
    "Permission",
    "ROLE_PERMISSIONS",
    "normalize_permission",
    "get_permissions_for_role",
    "AuthorizationError",
    "PermissionDeniedError",
    "ResourceAccessDeniedError",
    "has_permission",
    "authorize_action",
    "authorize_resource_access",
]
