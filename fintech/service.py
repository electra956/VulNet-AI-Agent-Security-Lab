"""
VulNet FinTech AI Agent Security Lab - FinTech Domain Service.
Provides business logic, deterministic data retrieval, and strict ownership validation
for simulated customers, accounts, and transactions.

SECURITY GUARANTEE:
Ownership validation is enforced programmatically in the service layer.
It does NOT rely on AI agent prompts, orchestrator rules, or user goodwill.
"""

from typing import Any, Dict, List, Optional
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


class FintechService:
    """
    Simulated banking service layer.
    Enforces strict customer-to-account ownership invariants.
    """

    def __init__(self, repository: Optional[FintechRepository] = None):
        self.repository = repository or FintechRepository()

    def get_customer(self, customer_id: str) -> Customer:
        """
        Retrieve customer by ID.
        Raises CustomerNotFoundError if customer does not exist.
        """
        cust = self.repository.get_customer(customer_id)
        if not cust:
            raise CustomerNotFoundError(f"Customer '{customer_id}' not found.")
        return cust

    def get_account(self, customer_id: str, account_id: str) -> Account:
        """
        Retrieve account by ID for a specific customer.
        Enforces:
        1. Customer must exist.
        2. Account must exist.
        3. Account MUST belong to customer_id.
        """
        # Validate customer exists
        self.get_customer(customer_id)

        # Validate account exists
        account = self.repository.get_account(account_id)
        if not account:
            raise AccountNotFoundError(f"Account '{account_id}' not found.")

        # Enforce ownership
        if account.customer_id != customer_id:
            raise UnauthorizedAccessError(
                f"Security Violation: Customer '{customer_id}' is not authorized to access account '{account_id}'."
            )

        return account

    def get_balance(self, customer_id: str, account_id: str) -> Dict[str, Any]:
        """
        Retrieve balance details for a specific account belonging to a customer.
        Enforces strict account ownership.
        """
        account = self.get_account(customer_id, account_id)
        return {
            "account_id": account.account_id,
            "customer_id": account.customer_id,
            "balance": account.balance,
            "currency": account.currency,
            "status": account.status,
            "account_type": account.account_type,
        }

    def get_transaction_history(self, customer_id: str, account_id: str) -> List[Transaction]:
        """
        Retrieve transaction history for a specific account.
        Enforces: customer must own account_id.
        """
        # Enforce account ownership first
        self.get_account(customer_id, account_id)

        # Return transactions involving this account
        return self.repository.list_transactions_for_account(account_id)

    def get_transaction(self, customer_id: str, transaction_id: str) -> Transaction:
        """
        Retrieve a specific transaction.
        Enforces:
        1. Customer must exist.
        2. Transaction must exist.
        3. Customer must own either the source or destination account of the transaction.
        """
        customer = self.get_customer(customer_id)
        txn = self.repository.get_transaction(transaction_id)
        if not txn:
            raise TransactionNotFoundError(f"Transaction '{transaction_id}' not found.")

        # Check if customer owns source or destination
        customer_accounts = set(customer.account_ids)
        if txn.source_account not in customer_accounts and txn.destination_account not in customer_accounts:
            raise UnauthorizedAccessError(
                f"Security Violation: Customer '{customer_id}' is not authorized to view transaction '{transaction_id}'."
            )

        return txn

    def list_customer_accounts(self, customer_id: str) -> List[Account]:
        """List all accounts owned by a validated customer."""
        self.get_customer(customer_id)
        return self.repository.list_accounts_for_customer(customer_id)
