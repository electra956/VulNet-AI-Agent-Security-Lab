"""
VulNet FinTech AI Agent Security Lab - Authorization & External Policy Enforcement.
Level 2 Step 6: FinTech RBAC and Authorization.

SECURITY GUARANTEES:
1. Authorization occurs strictly OUTSIDE the LLM.
2. The AI agent is never the final authorization authority.
3. Enforces both Role-Based Access Control (action permissions) and
   Object-Level Access Control (resource ownership invariants).
4. Directly prevents ASI03 (Identity and Privilege Abuse) and BOLA (Broken Object Level Authorization).
"""

import logging
from typing import Any, Dict, List, Optional, Union

from auth.roles import Role, normalize_role
from auth.permissions import Permission, normalize_permission, get_permissions_for_role
from fintech.repository import FintechRepository
from fintech.service import FintechService
from fintech.models import UnauthorizedAccessError

logger = logging.getLogger("vulnet.authorization")


class AuthorizationError(Exception):
    """Base exception for all authorization failures."""
    pass


class PermissionDeniedError(AuthorizationError):
    """Raised when a user's role lacks the required action permission."""
    pass


class ResourceAccessDeniedError(AuthorizationError):
    """Raised when a user attempts to access an unauthorized resource (e.g., cross-customer BOLA)."""
    pass


def has_permission(role: Union[Role, str], permission: Union[Permission, str]) -> bool:
    """
    Check if a given role is granted a specific permission.
    Returns boolean (True/False). Never raises on denied permission.
    """
    try:
        canonical_role = normalize_role(role)
        canonical_permission = normalize_permission(permission)
        granted_permissions = get_permissions_for_role(canonical_role)
        return canonical_permission in granted_permissions
    except (ValueError, KeyError):
        return False


def authorize_action(
    role: Union[Role, str],
    permission: Union[Permission, str],
    user_id: Optional[str] = None
) -> bool:
    """
    Enforce that a role possesses a required action permission.
    Raises PermissionDeniedError if the role lacks the permission.
    """
    canonical_role = normalize_role(role)
    canonical_permission = normalize_permission(permission)

    if not has_permission(canonical_role, canonical_permission):
        actor_desc = f"User '{user_id}' with role '{canonical_role.value}'" if user_id else f"Role '{canonical_role.value}'"
        msg = f"Access Denied: {actor_desc} lacks required permission '{canonical_permission.value}'."
        logger.warning("AUTHORIZATION_REJECTED: %s", msg)
        raise PermissionDeniedError(msg)

    return True


def authorize_resource_access(
    user_id: str,
    role: Union[Role, str],
    resource_type: str,
    resource_id: str,
    permission: Optional[Union[Permission, str]] = None,
    fintech_service: Optional[FintechService] = None,
) -> bool:
    """
    Authorizes access to a specific FinTech resource (e.g., account, transaction, customer profile).
    
    Enforces:
    1. Role Permission: Checks that the role has the appropriate action permission.
    2. Ownership Invariants: For CUSTOMER roles, strictly ensures that the customer owns
       the requested account, transaction, or profile.
       - CUST-001 can access ACC-1001.
       - CUST-001 CANNOT access ACC-2001 (owned by CUST-002).
       - CUST-001 CANNOT access transactions of CUST-002.
    
    Raises:
    - PermissionDeniedError if role lacks permission.
    - ResourceAccessDeniedError if customer attempts cross-customer resource access.
    """
    canonical_role = normalize_role(role)
    clean_type = resource_type.strip().lower()
    clean_id = resource_id.strip()
    clean_user = user_id.strip().upper()

    # Step 1: Infer and check action permission if not explicitly specified
    if permission is None:
        if clean_type in ("account", "account_balance", "balance"):
            required_perm = Permission.ACCOUNT_READ
        elif clean_type in ("transaction", "transaction_history", "transactions"):
            required_perm = Permission.TRANSACTION_READ
        elif clean_type in ("card", "card_details"):
            required_perm = Permission.CARD_READ
        elif clean_type in ("kyc", "kyc_data"):
            required_perm = Permission.KYC_READ
        else:
            required_perm = Permission.ACCOUNT_READ
    else:
        required_perm = normalize_permission(permission)

    # Validate action permission
    authorize_action(canonical_role, required_perm, user_id=clean_user)

    # Step 2: Ownership validation outside the LLM
    svc = fintech_service or FintechService()

    # Customer role is strictly partitioned to own resources
    if canonical_role == Role.CUSTOMER:
        if clean_type in ("account", "account_balance", "balance"):
            try:
                # Verifies that account exists AND customer owns it
                svc.get_account(customer_id=clean_user, account_id=clean_id)
            except UnauthorizedAccessError as exc:
                msg = f"Security Violation [ASI03]: Customer '{clean_user}' is not authorized to access account '{clean_id}' owned by another customer."
                logger.error("CROSS_ACCOUNT_ACCESS_BLOCKED: %s", msg)
                raise ResourceAccessDeniedError(msg) from exc
            except Exception as exc:
                # Re-raise or deny
                raise ResourceAccessDeniedError(f"Resource access denied for account '{clean_id}': {str(exc)}") from exc

        elif clean_type in ("transaction", "transaction_details"):
            try:
                # Verifies that transaction involves one of customer's accounts
                svc.get_transaction(customer_id=clean_user, transaction_id=clean_id)
            except UnauthorizedAccessError as exc:
                msg = f"Security Violation [ASI03]: Customer '{clean_user}' is not authorized to view transaction '{clean_id}'."
                logger.error("CROSS_TRANSACTION_ACCESS_BLOCKED: %s", msg)
                raise ResourceAccessDeniedError(msg) from exc
            except Exception as exc:
                raise ResourceAccessDeniedError(f"Resource access denied for transaction '{clean_id}': {str(exc)}") from exc

        elif clean_type in ("transaction_history", "customer", "customer_profile", "customer_history"):
            # Customer requesting another customer's data or history
            target_customer = clean_id.upper()
            if target_customer != clean_user:
                msg = f"Security Violation [ASI03]: Customer '{clean_user}' is not authorized to access data for customer '{clean_id}'."
                logger.error("CROSS_CUSTOMER_ACCESS_BLOCKED: %s", msg)
                raise ResourceAccessDeniedError(msg)

    return True
