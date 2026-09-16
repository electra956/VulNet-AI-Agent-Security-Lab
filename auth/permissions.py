"""
VulNet FinTech AI Agent Security Lab - Permissions and Role Mappings.
Level 2 Step 6: FinTech RBAC and Authorization.

Defines granular FinTech permissions:
- account.read
- transaction.read
- transaction.create
- transaction.cancel
- card.read
- card.freeze
- fraud.review
- kyc.read
- support.create
"""

from enum import Enum
from typing import Dict, Set, Union
from auth.roles import Role, normalize_role


class Permission(str, Enum):
    """
    Granular FinTech action permissions.
    """
    ACCOUNT_READ = "account.read"
    TRANSACTION_READ = "transaction.read"
    TRANSACTION_CREATE = "transaction.create"
    TRANSACTION_CANCEL = "transaction.cancel"
    CARD_READ = "card.read"
    CARD_FREEZE = "card.freeze"
    FRAUD_REVIEW = "fraud.review"
    KYC_READ = "kyc.read"
    SUPPORT_CREATE = "support.create"

    def __str__(self) -> str:
        return self.value


# Deterministic Role-Based Access Control (RBAC) Matrix
ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.CUSTOMER: {
        Permission.ACCOUNT_READ,
        Permission.TRANSACTION_READ,
        Permission.TRANSACTION_CREATE,
        Permission.CARD_READ,
        Permission.CARD_FREEZE,
        Permission.SUPPORT_CREATE,
    },
    Role.SUPPORT_AGENT: {
        Permission.ACCOUNT_READ,
        Permission.TRANSACTION_READ,
        Permission.CARD_READ,
        Permission.CARD_FREEZE,
        Permission.KYC_READ,
        Permission.SUPPORT_CREATE,
    },
    Role.FRAUD_ANALYST: {
        Permission.ACCOUNT_READ,
        Permission.TRANSACTION_READ,
        Permission.CARD_READ,
        Permission.CARD_FREEZE,
        Permission.FRAUD_REVIEW,
        Permission.KYC_READ,
        Permission.TRANSACTION_CANCEL,
        Permission.SUPPORT_CREATE,
    },
    Role.COMPLIANCE_ANALYST: {
        Permission.ACCOUNT_READ,
        Permission.TRANSACTION_READ,
        Permission.CARD_READ,
        Permission.FRAUD_REVIEW,
        Permission.KYC_READ,
    },
    Role.ADMIN: {
        Permission.ACCOUNT_READ,
        Permission.TRANSACTION_READ,
        Permission.TRANSACTION_CREATE,
        Permission.TRANSACTION_CANCEL,
        Permission.CARD_READ,
        Permission.CARD_FREEZE,
        Permission.FRAUD_REVIEW,
        Permission.KYC_READ,
        Permission.SUPPORT_CREATE,
    },
}


def normalize_permission(permission: Union[Permission, str]) -> Permission:
    """
    Normalize permission string or enum into a canonical Permission member.
    """
    if isinstance(permission, Permission):
        return permission

    if not permission or not isinstance(permission, str):
        raise ValueError(f"Invalid permission specification: {permission}")

    clean = permission.strip().lower()
    for perm in Permission:
        if perm.value == clean or perm.name.lower() == clean:
            return perm

    raise ValueError(f"Unknown or unsupported permission: '{permission}'")


def get_permissions_for_role(role: Union[Role, str]) -> Set[Permission]:
    """
    Retrieve the complete set of permissions granted to a given role.
    """
    canonical_role = normalize_role(role)
    return set(ROLE_PERMISSIONS.get(canonical_role, set()))
