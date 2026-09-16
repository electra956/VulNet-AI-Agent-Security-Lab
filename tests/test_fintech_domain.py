"""
Tests for Level 2 Step 2: Simulated FinTech Domain Layer.
Verifies customer lookup, account lookup, balance retrieval, transaction history,
unauthorized account access prevention, nonexistent accounts, and nonexistent customers.
"""

import pytest
from fintech.models import (
    Customer,
    Account,
    Transaction,
    CustomerNotFoundError,
    AccountNotFoundError,
    TransactionNotFoundError,
    UnauthorizedAccessError,
)
from fintech.repository import FintechRepository
from fintech.service import FintechService


@pytest.fixture
def fintech_service():
    """Provides a fresh FintechService instance with deterministic seed data."""
    repo = FintechRepository()
    return FintechService(repository=repo)


def test_valid_customer_lookup(fintech_service):
    """Verify retrieving a valid customer by ID."""
    cust = fintech_service.get_customer("CUST-001")
    assert cust.customer_id == "CUST-001"
    assert cust.name == "Alex Morgan"
    assert cust.role == "customer"
    assert "ACC-1001" in cust.account_ids
    assert "ACC-1002" in cust.account_ids


def test_valid_account_lookup(fintech_service):
    """Verify retrieving a valid account owned by the requesting customer."""
    acc = fintech_service.get_account("CUST-001", "ACC-1001")
    assert acc.account_id == "ACC-1001"
    assert acc.customer_id == "CUST-001"
    assert acc.balance == 5420.50
    assert acc.currency == "USD"
    assert acc.status == "ACTIVE"


def test_balance_retrieval(fintech_service):
    """Verify balance retrieval for an authorized customer account."""
    bal_info = fintech_service.get_balance("CUST-001", "ACC-1001")
    assert bal_info["account_id"] == "ACC-1001"
    assert bal_info["customer_id"] == "CUST-001"
    assert bal_info["balance"] == 5420.50
    assert bal_info["currency"] == "USD"
    assert bal_info["status"] == "ACTIVE"

    # Secondary account
    bal2 = fintech_service.get_balance("CUST-001", "ACC-1002")
    assert bal2["balance"] == 12850.00


def test_transaction_history(fintech_service):
    """Verify retrieving transaction history for an authorized account."""
    history = fintech_service.get_transaction_history("CUST-001", "ACC-1001")
    assert len(history) >= 3
    assert all(isinstance(t, Transaction) for t in history)
    # Check that each transaction involves ACC-1001
    for t in history:
        assert t.source_account == "ACC-1001" or t.destination_account == "ACC-1001"


def test_unauthorized_account_access(fintech_service):
    """
    CRITICAL SECURITY TEST:
    Verify that customer CUST-001 cannot access account ACC-2001 (owned by CUST-002).
    The service layer must raise UnauthorizedAccessError.
    """
    with pytest.raises(UnauthorizedAccessError) as excinfo:
        fintech_service.get_account("CUST-001", "ACC-2001")
    assert "not authorized" in str(excinfo.value).lower()

    # Balance check must also fail
    with pytest.raises(UnauthorizedAccessError):
        fintech_service.get_balance("CUST-001", "ACC-2001")

    # Transaction history check must also fail
    with pytest.raises(UnauthorizedAccessError):
        fintech_service.get_transaction_history("CUST-001", "ACC-2001")


def test_unauthorized_transaction_access(fintech_service):
    """
    Verify customer cannot view individual transactions of an account they do not own.
    TXN-20002 is between ACC-2001 and MERCHANT-GROCERY (owned by CUST-002).
    """
    with pytest.raises(UnauthorizedAccessError):
        fintech_service.get_transaction("CUST-001", "TXN-20002")

    # But CUST-002 can view it
    txn = fintech_service.get_transaction("CUST-002", "TXN-20002")
    assert txn.transaction_id == "TXN-20002"


def test_nonexistent_account(fintech_service):
    """Verify handling when an account ID does not exist."""
    with pytest.raises(AccountNotFoundError) as excinfo:
        fintech_service.get_account("CUST-001", "ACC-9999")
    assert "not found" in str(excinfo.value).lower()

    with pytest.raises(AccountNotFoundError):
        fintech_service.get_balance("CUST-001", "ACC-9999")


def test_nonexistent_customer(fintech_service):
    """Verify handling when a customer ID does not exist."""
    with pytest.raises(CustomerNotFoundError) as excinfo:
        fintech_service.get_customer("CUST-9999")
    assert "not found" in str(excinfo.value).lower()

    # Accessing an account with an invalid customer ID must also fail with CustomerNotFoundError
    with pytest.raises(CustomerNotFoundError):
        fintech_service.get_account("CUST-9999", "ACC-1001")


def test_list_customer_accounts(fintech_service):
    """Verify listing all accounts belonging to a customer."""
    accounts = fintech_service.list_customer_accounts("CUST-001")
    assert len(accounts) == 2
    acc_ids = {a.account_id for a in accounts}
    assert acc_ids == {"ACC-1001", "ACC-1002"}
