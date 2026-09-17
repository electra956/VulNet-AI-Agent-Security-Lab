"""
VulNet FinTech AI Agent Security Lab - FinTech Domain Service.
Provides business logic, deterministic data retrieval, and strict ownership validation
for simulated customers, accounts, and transactions.

SECURITY GUARANTEE:
Ownership validation is enforced programmatically in the service layer.
It does NOT rely on AI agent prompts, orchestrator rules, or user goodwill.
"""

from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from fintech.models import (
    Customer,
    Account,
    Transaction,
    TransactionStatus,
    CustomerNotFoundError,
    AccountNotFoundError,
    TransactionNotFoundError,
    UnauthorizedAccessError,
    TransactionValidationError,
    InvalidStateTransitionError,
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

    def create_transaction_record(
        self,
        request_id: str,
        session_id: str,
        user_id: str,
        source_account_id: str,
        destination_account_id: str,
        amount: float,
        currency: str = "USD",
        transaction_type: str = "TRANSFER",
        status: str = TransactionStatus.PENDING.value,
        risk_level: str = "LOW",
        approval_status: str = "NONE",
        reason: str = "",
        description: str = "",
    ) -> Transaction:
        """Create and register a new deterministic simulated transaction."""
        txn_id = f"TXN-SIM-{datetime.now().strftime('%Y%m%d%H%M%S%f')[:17]}"
        txn = Transaction(
            transaction_id=txn_id,
            request_id=request_id,
            session_id=session_id,
            user_id=user_id,
            source_account_id=source_account_id,
            destination_account_id=destination_account_id,
            amount=amount,
            currency=currency,
            transaction_type=transaction_type,
            status=status,
            risk_level=risk_level,
            approval_status=approval_status,
            reason=reason,
            description=description or f"Simulated {transaction_type} of {currency} {amount:,.2f}"
        )
        return self.repository.save_transaction(txn)

    def execute_transfer(
        self,
        customer_id: str,
        from_account_id: str,
        to_account_id: str,
        amount: float,
        request_id: str = "",
        session_id: str = "",
        currency: str = "USD",
        description: str = "Simulated Transfer",
    ) -> Transaction:
        """
        Execute simulated fund transfer between accounts.
        Enforces:
        1. Customer must exist.
        2. Customer must own from_account_id.
        3. from_account_id != to_account_id.
        4. amount > 0.
        5. Available balance >= amount.
        6. Updates balances and records COMPLETED transaction.
        """
        # Validate ownership outside LLM
        src_account = self.get_account(customer_id, from_account_id)

        if from_account_id == to_account_id:
            raise TransactionValidationError(
                f"Destination account '{to_account_id}' cannot be identical to source account."
            )

        if amount <= 0:
            raise TransactionValidationError(
                f"Transfer amount must be positive, got {amount}."
            )

        if src_account.balance < amount:
            raise TransactionValidationError(
                f"Insufficient funds: account '{from_account_id}' balance (${src_account.balance:,.2f}) "
                f"is less than requested amount (${amount:,.2f})."
            )

        # Atomic simulated balance update
        new_src_balance = round(src_account.balance - amount, 2)
        self.repository.update_account_balance(from_account_id, new_src_balance)

        # Credit destination if internal
        dest_account = self.repository.get_account(to_account_id)
        if dest_account:
            new_dest_balance = round(dest_account.balance + amount, 2)
            self.repository.update_account_balance(to_account_id, new_dest_balance)

        # Create completed transaction entity
        txn_id = f"TXN-SIM-{datetime.now().strftime('%Y%m%d%H%M%S%f')[:17]}"
        txn = Transaction(
            transaction_id=txn_id,
            request_id=request_id,
            session_id=session_id,
            user_id=customer_id,
            source_account_id=from_account_id,
            destination_account_id=to_account_id,
            amount=amount,
            currency=currency,
            transaction_type="TRANSFER",
            status=TransactionStatus.COMPLETED.value,
            risk_level="LOW",
            approval_status="NONE",
            reason="Standard simulated transfer executed successfully.",
            description=description,
        )
        return self.repository.save_transaction(txn)

    def transition_transaction(
        self,
        transaction_id: str,
        new_status: str,
        reason: str = ""
    ) -> Transaction:
        """Explicitly transition an existing transaction's state."""
        txn = self.repository.get_transaction(transaction_id)
        if not txn:
            raise TransactionNotFoundError(f"Transaction '{transaction_id}' not found.")
        txn.transition_to(new_status, reason=reason)
        return self.repository.save_transaction(txn)

