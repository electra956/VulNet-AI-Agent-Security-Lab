"""
VulNet FinTech AI Agent Security Lab - Roles and Hierarchy.
Level 2 Step 6: FinTech RBAC and Authorization.

Defines standard FinTech persona roles:
- CUSTOMER
- SUPPORT_AGENT
- FRAUD_ANALYST
- COMPLIANCE_ANALYST
- ADMIN
"""

from enum import Enum
from typing import Union


class Role(str, Enum):
    """
    Standard FinTech Role taxonomy for RBAC enforcement.
    """
    CUSTOMER = "CUSTOMER"
    SUPPORT_AGENT = "SUPPORT_AGENT"
    FRAUD_ANALYST = "FRAUD_ANALYST"
    COMPLIANCE_ANALYST = "COMPLIANCE_ANALYST"
    ADMIN = "ADMIN"

    def __str__(self) -> str:
        return self.value


def normalize_role(role: Union[Role, str]) -> Role:
    """
    Normalize any role representation (string, enum, lowercase, uppercase)
    into a canonical Role enum member.
    """
    if isinstance(role, Role):
        return role

    if not role or not isinstance(role, str):
        raise ValueError(f"Invalid role specification: {role}")

    clean = role.strip().upper()

    # Mappings for backward compatibility with existing user models
    mapping = {
        "CUSTOMER": Role.CUSTOMER,
        "SUPPORT": Role.SUPPORT_AGENT,
        "SUPPORT_AGENT": Role.SUPPORT_AGENT,
        "FRAUD": Role.FRAUD_ANALYST,
        "FRAUD_ANALYST": Role.FRAUD_ANALYST,
        "COMPLIANCE": Role.COMPLIANCE_ANALYST,
        "COMPLIANCE_ANALYST": Role.COMPLIANCE_ANALYST,
        "ADMIN": Role.ADMIN,
        "ADMINISTRATOR": Role.ADMIN,
    }

    if clean in mapping:
        return mapping[clean]

    raise ValueError(f"Unknown or unsupported role: '{role}'")
