"""
VulNet FinTech AI Agent Security Lab - In-Memory Deterministic Repository.
Holds static mock data for simulated customers, accounts, and transactions.
No network, database, or production credentials required.
"""

from typing import Dict, List, Optional
from fintech.models import Customer, Account, Transaction


def get_default_customers() -> Dict[str, Customer]:
    """Return deterministic seed customer entities."""
    return {
        "CUST-001": Customer(
            customer_id="CUST-001",
            name="Alex Morgan",
            role="customer",
            account_ids=["ACC-1001", "ACC-1002"],
            status="ACTIVE",
            tier="Retail Standard",
            created_at="2026-01-15T09:00:00Z"
        ),
        "CUST-002": Customer(
            customer_id="CUST-002",
            name="Jordan Lee",
            role="customer",
            account_ids=["ACC-2001"],
            status="ACTIVE",
            tier="Retail Standard",
            created_at="2026-02-20T11:30:00Z"
        ),
    }


def get_default_accounts() -> Dict[str, Account]:
    """Return deterministic seed account entities."""
    return {
        "ACC-1001": Account(
            account_id="ACC-1001",
            customer_id="CUST-001",
            balance=5420.50,
            currency="USD",
            status="ACTIVE",
            account_type="Premier Checking"
        ),
        "ACC-1002": Account(
            account_id="ACC-1002",
            customer_id="CUST-001",
            balance=12850.00,
            currency="USD",
            status="ACTIVE",
            account_type="High-Yield Savings"
        ),
        "ACC-2001": Account(
            account_id="ACC-2001",
            customer_id="CUST-002",
            balance=3100.25,
            currency="USD",
            status="ACTIVE",
            account_type="Standard Checking"
        ),
    }


def get_default_transactions() -> Dict[str, Transaction]:
    """Return deterministic seed transaction records."""
    return {
        "TXN-10001": Transaction(
            transaction_id="TXN-10001",
            source_account="EXTERNAL-PAYROLL",
            destination_account="ACC-1001",
            amount=3200.00,
            currency="USD",
            timestamp="2026-09-16T08:14:22Z",
            status="COMPLETED",
            category="INCOME",
            description="Payroll Direct Deposit - Acme Corp"
        ),
        "TXN-10002": Transaction(
            transaction_id="TXN-10002",
            source_account="ACC-1001",
            destination_account="MERCHANT-COFFEE",
            amount=5.75,
            currency="USD",
            timestamp="2026-09-15T18:45:10Z",
            status="COMPLETED",
            category="FOOD_AND_BEVERAGE",
            description="Coffee Bean - Point of Sale"
        ),
        "TXN-10003": Transaction(
            transaction_id="TXN-10003",
            source_account="ACC-1001",
            destination_account="UTILITY-METRO",
            amount=142.50,
            currency="USD",
            timestamp="2026-09-14T11:20:05Z",
            status="COMPLETED",
            category="UTILITIES",
            description="Metro Electric Utility Bill"
        ),
        "TXN-10004": Transaction(
            transaction_id="TXN-10004",
            source_account="ACC-1001",
            destination_account="ACC-1002",
            amount=500.00,
            currency="USD",
            timestamp="2026-09-13T10:00:00Z",
            status="COMPLETED",
            category="INTERNAL_TRANSFER",
            description="Scheduled Monthly Savings Transfer"
        ),
        "TXN-20001": Transaction(
            transaction_id="TXN-20001",
            source_account="EXTERNAL-WIRE",
            destination_account="ACC-2001",
            amount=1500.00,
            currency="USD",
            timestamp="2026-09-12T14:30:00Z",
            status="COMPLETED",
            category="TRANSFER",
            description="Inbound Wire Deposit - Freelance Client"
        ),
        "TXN-20002": Transaction(
            transaction_id="TXN-20002",
            source_account="ACC-2001",
            destination_account="MERCHANT-GROCERY",
            amount=84.20,
            currency="USD",
            timestamp="2026-09-11T16:20:00Z",
            status="COMPLETED",
            category="GROCERIES",
            description="Fresh Market Point of Sale"
        ),
    }


class FintechRepository:
    """
    Thread-safe, deterministic repository for synthetic financial entities.
    """

    def __init__(self):
        self.customers: Dict[str, Customer] = get_default_customers()
        self.accounts: Dict[str, Account] = get_default_accounts()
        self.transactions: Dict[str, Transaction] = get_default_transactions()

    def get_customer(self, customer_id: str) -> Optional[Customer]:
        return self.customers.get(customer_id)

    def get_account(self, account_id: str) -> Optional[Account]:
        return self.accounts.get(account_id)

    def get_transaction(self, transaction_id: str) -> Optional[Transaction]:
        return self.transactions.get(transaction_id)

    def list_accounts_for_customer(self, customer_id: str) -> List[Account]:
        return [acc for acc in self.accounts.values() if acc.customer_id == customer_id]

    def list_transactions_for_account(self, account_id: str) -> List[Transaction]:
        return [
            t for t in self.transactions.values()
            if t.source_account == account_id or t.destination_account == account_id
        ]

    def reset(self) -> None:
        """Reset repository to initial deterministic seed state."""
        self.customers = get_default_customers()
        self.accounts = get_default_accounts()
        self.transactions = get_default_transactions()
