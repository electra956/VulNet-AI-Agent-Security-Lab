"""
VulNet FinTech AI Agent Security Lab - Domain Models & Exceptions.
Provides data structures for synthetic customers, accounts, and transactions.
All entities are strictly simulated for educational and security testing.
"""

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


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


@dataclass
class Transaction:
    """
    Synthetic financial ledger transaction record.
    """
    transaction_id: str
    source_account: str
    destination_account: str
    amount: float
    currency: str = "USD"
    timestamp: str = "2026-09-16T08:00:00Z"
    status: str = "COMPLETED"
    category: str = "GENERAL"
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
