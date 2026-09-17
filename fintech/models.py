"""
VulNet FinTech AI Agent Security Lab - Domain Models & Exceptions.
Provides data structures for synthetic customers, accounts, and transactions.
All entities are strictly simulated for educational and security testing.
"""

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set, Union


class FintechError(Exception):
    """Base exception for fintech domain errors."""
    pass


class CustomerNotFoundError(FintechError):
    """Raised when a requested customer ID does not exist."""
    pass


class AccountNotFoundError(FintechError):
    """Raised when a requested account ID does not exist."""
    pass


class TransactionNotFoundError(FintechError):
    """Raised when a requested transaction ID does not exist."""
    pass


class UnauthorizedAccessError(FintechError):
    """Raised when a customer attempts to access an account or transaction they do not own."""
    pass


@dataclass
class Customer:
    """
    Synthetic banking customer entity.
    """
    customer_id: str
    name: str
    role: str = "customer"
    account_ids: List[str] = field(default_factory=list)
    status: str = "ACTIVE"
    tier: str = "Retail Standard"
    created_at: str = "2026-01-15T09:00:00Z"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Account:
    """
    Synthetic banking account entity.
    """
    account_id: str
    customer_id: str
    balance: float
    currency: str = "USD"
    status: str = "ACTIVE"
    account_type: str = "Checking"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


from enum import Enum
from datetime import datetime, timezone


class TransactionStatus(str, Enum):
    """
    Deterministic simulated transaction states conforming to Step 17.
    """
    PENDING = "PENDING"
    RISK_CHECK = "RISK_CHECK"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVED = "APPROVED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"

    def __str__(self) -> str:
        return self.value


# Deterministic explicit state transitions
VALID_STATE_TRANSITIONS: Dict[str, Set[str]] = {
    TransactionStatus.PENDING.value: {
        TransactionStatus.RISK_CHECK.value,
        TransactionStatus.APPROVAL_REQUIRED.value,
        TransactionStatus.APPROVED.value,
        TransactionStatus.PROCESSING.value,
        TransactionStatus.REJECTED.value,
        TransactionStatus.CANCELLED.value,
        TransactionStatus.FAILED.value,
    },
    TransactionStatus.RISK_CHECK.value: {
        TransactionStatus.APPROVAL_REQUIRED.value,
        TransactionStatus.APPROVED.value,
        TransactionStatus.PROCESSING.value,
        TransactionStatus.REJECTED.value,
        TransactionStatus.CANCELLED.value,
        TransactionStatus.FAILED.value,
    },
    TransactionStatus.APPROVAL_REQUIRED.value: {
        TransactionStatus.APPROVED.value,
        TransactionStatus.REJECTED.value,
        TransactionStatus.CANCELLED.value,
    },
    TransactionStatus.APPROVED.value: {
        TransactionStatus.PROCESSING.value,
        TransactionStatus.CANCELLED.value,
    },
    TransactionStatus.PROCESSING.value: {
        TransactionStatus.COMPLETED.value,
        TransactionStatus.FAILED.value,
    },
    TransactionStatus.COMPLETED.value: set(),
    TransactionStatus.REJECTED.value: set(),
    TransactionStatus.CANCELLED.value: set(),
    TransactionStatus.FAILED.value: set(),
}


class InvalidStateTransitionError(FintechError):
    """Raised when an illegal transaction state transition is attempted."""
    pass


class TransactionValidationError(FintechError):
    """Raised when transaction attributes fail domain validation."""
    pass


@dataclass
class Transaction:
    """
    Structured representation of a simulated FinTech financial transaction.
    Conforms to Step 17 Phase 4 specification.
    Contains zero real credentials, secrets, or banking connections.
    """
    transaction_id: str
    request_id: str = ""
    session_id: str = ""
    user_id: str = ""
    source_account_id: str = ""
    destination_account_id: str = ""
    amount: float = 0.0
    currency: str = "USD"
    transaction_type: str = "TRANSFER"
    status: str = TransactionStatus.COMPLETED.value
    risk_level: str = "LOW"
    approval_status: str = "NONE"
    created_at: str = ""
    updated_at: str = ""
    reason: str = ""
    category: str = "GENERAL"
    description: str = ""

    def __init__(
        self,
        transaction_id: str,
        request_id: str = "",
        session_id: str = "",
        user_id: str = "",
        source_account_id: str = "",
        destination_account_id: str = "",
        amount: float = 0.0,
        currency: str = "USD",
        transaction_type: str = "TRANSFER",
        status: str = TransactionStatus.COMPLETED.value,
        risk_level: str = "LOW",
        approval_status: str = "NONE",
        created_at: str = "",
        updated_at: str = "",
        reason: str = "",
        category: str = "GENERAL",
        description: str = "",
        # Backward compatibility aliases
        source_account: Optional[str] = None,
        destination_account: Optional[str] = None,
        timestamp: Optional[str] = None,
    ):
        self.transaction_id = transaction_id
        self.request_id = request_id
        self.session_id = session_id
        self.user_id = user_id
        self.source_account_id = source_account_id or (source_account or "")
        self.destination_account_id = destination_account_id or (destination_account or "")
        self.amount = float(amount)
        self.currency = currency
        self.transaction_type = transaction_type
        self.status = status
        self.risk_level = risk_level
        self.approval_status = approval_status
        now_iso = datetime.now(timezone.utc).isoformat()
        self.created_at = created_at or (timestamp or now_iso)
        self.updated_at = updated_at or self.created_at
        self.reason = reason
        self.category = category
        self.description = description or f"Simulated {transaction_type}"

    @property
    def source_account(self) -> str:
        return self.source_account_id

    @source_account.setter
    def source_account(self, value: str) -> None:
        self.source_account_id = value

    @property
    def destination_account(self) -> str:
        return self.destination_account_id

    @destination_account.setter
    def destination_account(self, value: str) -> None:
        self.destination_account_id = value

    @property
    def timestamp(self) -> str:
        return self.created_at

    @timestamp.setter
    def timestamp(self, value: str) -> None:
        self.created_at = value

    def transition_to(self, new_status: Union[TransactionStatus, str], reason: str = "") -> None:
        """
        Transition transaction to a new deterministic state following VALID_STATE_TRANSITIONS.
        """
        target = new_status.value if isinstance(new_status, TransactionStatus) else str(new_status).upper()
        allowed = VALID_STATE_TRANSITIONS.get(self.status, set())
        if target not in allowed:
            raise InvalidStateTransitionError(
                f"Illegal state transition from '{self.status}' to '{target}'. "
                f"Allowed transitions: {list(allowed)}"
            )
        self.status = target
        if reason:
            self.reason = reason
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transaction_id": self.transaction_id,
            "request_id": self.request_id,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "source_account_id": self.source_account_id,
            "destination_account_id": self.destination_account_id,
            "source_account": self.source_account_id,
            "destination_account": self.destination_account_id,
            "amount": self.amount,
            "currency": self.currency,
            "transaction_type": self.transaction_type,
            "status": self.status,
            "risk_level": self.risk_level,
            "approval_status": self.approval_status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "timestamp": self.created_at,
            "reason": self.reason,
            "category": self.category,
            "description": self.description,
        }
