"""
VulNet AI Agent Security Lab - Simulated FinTech Tool Suite
Level 2 Step 12: Simulated FinTech Tool Ecosystem

Provides 16 simulated educational banking tools across 6 categories:
1. ACCOUNT: get_account_balance, get_account_status, get_customer_profile, get_transaction_history
2. PAYMENT: create_payment, schedule_payment, cancel_payment
3. CARD: get_card_status, freeze_card, unfreeze_card
4. FRAUD: check_transaction_risk, flag_transaction, get_fraud_case
5. KYC: get_kyc_status, verify_identity_simulated
6. SUPPORT: create_support_ticket, send_simulated_notification

SECURITY & SAFETY GUARANTEES:
- All tools operate strictly on local synthetic in-memory state.
- Zero external bank APIs, payment networks (ACH, SWIFT, UPI), or real money movement.
- Strict object-level ownership checks (BOLA prevention): Customers can only view/transact on their own accounts.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from fintech.risk.transaction_risk import TransactionRiskEngine


class FinTechToolSuite:
    """
    Stateful in-memory synthetic FinTech tool implementations for the lab.
    """

    def __init__(self):
        self.risk_engine = TransactionRiskEngine()
        self._reset_synthetic_state()

    def _reset_synthetic_state(self) -> None:
        """Initialize synthetic in-memory banking records."""
        # 1. Customers
        self.customers: Dict[str, Dict[str, Any]] = {
            "CUST-001": {
                "customer_id": "CUST-001",
                "name": "Alex Morgan",
                "role": "CUSTOMER",
                "tier": "Retail Standard",
                "kyc_status": "VERIFIED",
                "created_at": "2026-01-15T09:00:00Z"
            },
            "CUST-002": {
                "customer_id": "CUST-002",
                "name": "Jordan Lee",
                "role": "CUSTOMER",
                "tier": "Retail Standard",
                "kyc_status": "VERIFIED",
                "created_at": "2026-02-20T11:30:00Z"
            }
        }

        # 2. Accounts
        self.accounts: Dict[str, Dict[str, Any]] = {
            "ACC-1001": {
                "account_id": "ACC-1001",
                "customer_id": "CUST-001",
                "balance": 5420.50,
                "currency": "USD",
                "status": "ACTIVE",
                "account_type": "Premier Checking"
            },
            "ACC-1002": {
                "account_id": "ACC-1002",
                "customer_id": "CUST-001",
                "balance": 12850.00,
                "currency": "USD",
                "status": "ACTIVE",
                "account_type": "High-Yield Savings"
            },
            "ACC-2001": {
                "account_id": "ACC-2001",
                "customer_id": "CUST-002",
                "balance": 3100.25,
                "currency": "USD",
                "status": "ACTIVE",
                "account_type": "Standard Checking"
            }
        }

        # 3. Cards
        self.cards: Dict[str, Dict[str, Any]] = {
            "CARD-1001": {
                "card_id": "CARD-1001",
                "customer_id": "CUST-001",
                "account_id": "ACC-1001",
                "card_type": "DEBIT",
                "status": "ACTIVE",
                "last_four": "4321",
                "expiry": "12/28"
            },
            "CARD-2001": {
                "card_id": "CARD-2001",
                "customer_id": "CUST-002",
                "account_id": "ACC-2001",
                "card_type": "DEBIT",
                "status": "ACTIVE",
                "last_four": "8765",
                "expiry": "09/27"
            }
        }

        # 4. Transactions
        self.transactions: List[Dict[str, Any]] = [
            {
                "transaction_id": "TXN-10001",
                "source_account": "EXTERNAL-PAYROLL",
                "destination_account": "ACC-1001",
                "amount": 3200.00,
                "currency": "USD",
                "timestamp": "2026-09-16T08:14:22Z",
                "status": "COMPLETED",
                "description": "Payroll Direct Deposit - Acme Corp"
            },
            {
                "transaction_id": "TXN-10002",
                "source_account": "ACC-1001",
                "destination_account": "MERCHANT-COFFEE",
                "amount": 5.75,
                "currency": "USD",
                "timestamp": "2026-09-15T18:45:10Z",
                "status": "COMPLETED",
                "description": "Coffee Bean - Point of Sale"
            },
            {
                "transaction_id": "TXN-20001",
                "source_account": "ACC-2001",
                "destination_account": "MERCHANT-GROCERY",
                "amount": 78.50,
                "currency": "USD",
                "timestamp": "2026-09-14T14:20:00Z",
                "status": "COMPLETED",
                "description": "Supermarket Grocery"
            }
        ]

        # 5. Scheduled Payments
        self.scheduled_payments: Dict[str, Dict[str, Any]] = {}

        # 6. Fraud Cases
        self.fraud_cases: Dict[str, Dict[str, Any]] = {
            "CASE-9001": {
                "case_id": "CASE-9001",
                "transaction_id": "TXN-10002",
                "status": "UNDER_INVESTIGATION",
                "reason": "Unusual merchant location flag",
                "created_at": "2026-09-16T09:00:00Z"
            }
        }

        # 7. Support Tickets
        self.support_tickets: Dict[str, Dict[str, Any]] = {}

        # 8. Simulated Notifications
        self.notifications: List[Dict[str, Any]] = []

    # =========================================================================
    # OWNERSHIP VALIDATION HELPER
    # =========================================================================
    def _validate_ownership(
        self,
        customer_id: Optional[str],
        account_id: Optional[str] = None,
        card_id: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Enforce that customer_id owns the requested account or card.
        Returns error dict if unauthorized, None if allowed.
        """
        if not customer_id or customer_id in ("ADMIN", "FRAUD-001", "SUPPORT-001", "ADMIN-001"):
            # Internal roles with elevated oversight skip customer self-ownership restriction
            return None

        if account_id:
            account = self.accounts.get(account_id)
            if not account:
                return {"status": "error", "reason": f"Account '{account_id}' not found."}
            if account["customer_id"] != customer_id:
                return {
                    "status": "blocked",
                    "reason": f"Access Denied: Customer '{customer_id}' does not own account '{account_id}'."
                }

        if card_id:
            card = self.cards.get(card_id)
            if not card:
                return {"status": "error", "reason": f"Card '{card_id}' not found."}
            if card["customer_id"] != customer_id:
                return {
                    "status": "blocked",
                    "reason": f"Access Denied: Customer '{customer_id}' does not own card '{card_id}'."
                }

        return None

    # =========================================================================
    # 1. ACCOUNT CATEGORY
    # =========================================================================
    def get_account_balance(self, account_id: str, customer_id: Optional[str] = None) -> Dict[str, Any]:
        """Retrieve balance details for an account."""
        owner_err = self._validate_ownership(customer_id, account_id=account_id)
        if owner_err:
            return owner_err

        account = self.accounts.get(account_id)
        if not account:
            return {"status": "error", "reason": f"Account '{account_id}' not found."}

        return {
            "status": "success",
            "tool": "get_account_balance",
            "risk_level": "LOW",
            "result": {
                "account_id": account["account_id"],
                "customer_id": account["customer_id"],
                "balance": account["balance"],
                "currency": account["currency"],
                "status": account["status"]
            }
        }

    def get_account_status(self, account_id: str, customer_id: Optional[str] = None) -> Dict[str, Any]:
        """Retrieve status, account type, and operational posture of an account."""
        owner_err = self._validate_ownership(customer_id, account_id=account_id)
        if owner_err:
            return owner_err

        account = self.accounts.get(account_id)
        if not account:
            return {"status": "error", "reason": f"Account '{account_id}' not found."}

        return {
            "status": "success",
            "tool": "get_account_status",
            "risk_level": "LOW",
            "result": {
                "account_id": account["account_id"],
                "customer_id": account["customer_id"],
                "status": account["status"],
                "account_type": account["account_type"],
                "currency": account["currency"]
            }
        }

    def get_customer_profile(self, customer_id: str) -> Dict[str, Any]:
        """Retrieve customer profile and associated account IDs."""
        cust = self.customers.get(customer_id)
        if not cust:
            return {"status": "error", "reason": f"Customer '{customer_id}' not found."}

        owned_accounts = [acc_id for acc_id, acc in self.accounts.items() if acc["customer_id"] == customer_id]

        return {
            "status": "success",
            "tool": "get_customer_profile",
            "risk_level": "LOW",
            "result": {
                "customer_id": cust["customer_id"],
                "name": cust["name"],
                "role": cust["role"],
                "tier": cust["tier"],
                "kyc_status": cust["kyc_status"],
                "account_ids": owned_accounts,
                "created_at": cust["created_at"]
            }
        }

    def get_transaction_history(
        self,
        account_id: str,
        customer_id: Optional[str] = None,
        limit: int = 10
    ) -> Dict[str, Any]:
        """Retrieve transaction history for an account."""
        owner_err = self._validate_ownership(customer_id, account_id=account_id)
        if owner_err:
            return owner_err

        if account_id not in self.accounts:
            return {"status": "error", "reason": f"Account '{account_id}' not found."}

        txns = [
            t for t in self.transactions
            if t["source_account"] == account_id or t["destination_account"] == account_id
        ]
        return {
            "status": "success",
            "tool": "get_transaction_history",
            "risk_level": "LOW",
            "result": {
                "account_id": account_id,
                "count": min(len(txns), limit),
                "transactions": txns[:limit]
            }
        }

    # =========================================================================
    # 2. PAYMENT CATEGORY
    # =========================================================================
    def create_payment(
        self,
        from_account: str,
        to_account: str,
        amount: float,
        customer_id: Optional[str] = None,
        description: str = "Simulated Transfer"
    ) -> Dict[str, Any]:
        """Simulate fund transfer between accounts (High Risk, Requires Approval)."""
        owner_err = self._validate_ownership(customer_id, account_id=from_account)
        if owner_err:
            return owner_err

        src = self.accounts.get(from_account)
        if not src:
            return {"status": "error", "reason": f"Source account '{from_account}' not found."}

        if amount <= 0:
            return {"status": "error", "reason": f"Payment amount must be positive, got {amount}."}

        if src["balance"] < amount:
            return {
                "status": "error",
                "reason": f"Insufficient funds: account '{from_account}' has balance {src['balance']} < {amount}."
            }

        # Deduct from source
        src["balance"] = round(src["balance"] - amount, 2)

        # Credit destination if local
        if to_account in self.accounts:
            self.accounts[to_account]["balance"] = round(self.accounts[to_account]["balance"] + amount, 2)

        txn_id = f"TXN-SIM-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        new_txn = {
            "transaction_id": txn_id,
            "source_account": from_account,
            "destination_account": to_account,
            "amount": amount,
            "currency": src["currency"],
            "timestamp": datetime.now().isoformat(),
            "status": "COMPLETED",
            "description": description
        }
        self.transactions.insert(0, new_txn)

        return {
            "status": "success",
            "tool": "create_payment",
            "risk_level": "HIGH",
            "result": {
                "transaction_id": txn_id,
                "from_account": from_account,
                "to_account": to_account,
                "amount": amount,
                "remaining_balance": src["balance"],
                "status": "SIMULATED_TRANSFERRED",
                "real_funds_moved": False
            }
        }

    def create_simulated_transaction(
        self,
        from_account: str,
        to_account: str,
        amount: float,
        customer_id: Optional[str] = None,
        currency: str = "USD",
        description: str = "Simulated Transfer",
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        caller_role: Any = "CUSTOMER",
        user_authorized: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Execute simulated transaction through MCP Gateway (Step 17).
        Enforces independent MCP-layer authorization:
        1. Authenticated customer check
        2. Role & permission check (Permission.TRANSACTION_CREATE)
        3. Source account ownership validation (BOLA prevention)
        4. Destination account validation (valid, != from_account)
        5. Amount validation (> 0, <= available balance)
        6. Deterministic risk check & human approval gate
        7. In-memory ledger update and audit record generation
        """
        if not customer_id:
            return {
                "status": "blocked",
                "decision": "DENY",
                "tool": "create_simulated_transaction",
                "reason": "Missing authenticated customer identity."
            }

        # Validate role permission
        from auth.permissions import Permission
        from auth.authorization import has_permission
        from auth.roles import normalize_role
        try:
            role_norm = normalize_role(caller_role)
            if not has_permission(role_norm, Permission.TRANSACTION_CREATE):
                return {
                    "status": "blocked",
                    "decision": "DENY",
                    "tool": "create_simulated_transaction",
                    "reason": f"Insufficient privilege: Role '{role_norm.value}' lacks permission '{Permission.TRANSACTION_CREATE.value}'."
                }
        except Exception:
            pass

        # Validate source account & ownership
        src = self.accounts.get(from_account)
        if not src:
            return {
                "status": "error",
                "decision": "DENY",
                "tool": "create_simulated_transaction",
                "reason": f"Source account '{from_account}' not found."
            }

        if src["customer_id"] != customer_id:
            return {
                "status": "blocked",
                "decision": "DENY",
                "tool": "create_simulated_transaction",
                "reason": f"Unauthorized: Customer '{customer_id}' does not own account '{from_account}'."
            }

        # Validate destination account
        if from_account == to_account:
            return {
                "status": "error",
                "decision": "DENY",
                "tool": "create_simulated_transaction",
                "reason": "Destination account cannot be identical to source account."
            }

        # Validate amount
        try:
            amt = float(amount)
        except (ValueError, TypeError):
            return {
                "status": "error",
                "decision": "DENY",
                "tool": "create_simulated_transaction",
                "reason": f"Invalid transaction amount: {amount}."
            }

        if amt <= 0:
            return {
                "status": "error",
                "decision": "DENY",
                "tool": "create_simulated_transaction",
                "reason": f"Payment amount must be positive, got {amt}."
            }

        # Evaluate risk deterministically before execution
        risk_eval = self.risk_engine.evaluate({
            "amount": amt,
            "from_account": from_account,
            "to_account": to_account,
            "available_balance": src["balance"]
        })

        is_high_risk = (
            risk_eval.risk_level in ("HIGH", "CRITICAL")
            or risk_eval.decision in ("REVIEW", "BLOCK")
            or amt >= 10000.0
        )

        if is_high_risk and not user_authorized:
            return {
                "status": "blocked",
                "decision": "DENY",
                "tool": "create_simulated_transaction",
                "risk_level": risk_eval.risk_level,
                "reason": f"High-risk transaction (${amt:,.2f}) requires explicit human authorization.",
                "requires_approval": True
            }

        if risk_eval.decision == "BLOCK":
            return {
                "status": "blocked",
                "decision": "DENY",
                "tool": "create_simulated_transaction",
                "risk_level": risk_eval.risk_level,
                "reason": f"Transaction blocked by risk policy: {', '.join(risk_eval.reasons)}."
            }

        if src["balance"] < amt:
            return {
                "status": "error",
                "decision": "DENY",
                "tool": "create_simulated_transaction",
                "reason": f"Insufficient funds: account '{from_account}' has balance ${src['balance']:,.2f} < ${amt:,.2f}."
            }

        if risk_eval.decision == "BLOCK":
            return {
                "status": "blocked",
                "decision": "DENY",
                "tool": "create_simulated_transaction",
                "risk_level": "CRITICAL",
                "reason": "Transaction blocked by risk policy."
            }

        # Deduct from source
        src["balance"] = round(src["balance"] - amt, 2)

        # Credit destination if internal
        if to_account in self.accounts:
            self.accounts[to_account]["balance"] = round(self.accounts[to_account]["balance"] + amt, 2)

        txn_id = f"TXN-SIM-{datetime.now().strftime('%Y%m%d%H%M%S%f')[:17]}"
        new_txn = {
            "transaction_id": txn_id,
            "request_id": request_id or "",
            "session_id": session_id or "",
            "user_id": customer_id,
            "source_account": from_account,
            "source_account_id": from_account,
            "destination_account": to_account,
            "destination_account_id": to_account,
            "amount": amt,
            "currency": currency,
            "timestamp": datetime.now().isoformat(),
            "status": "COMPLETED",
            "risk_level": risk_eval.risk_level,
            "approval_status": "APPROVED" if user_authorized else "NONE",
            "category": "TRANSFER",
            "description": description
        }
        self.transactions.insert(0, new_txn)

        return {
            "status": "success",
            "tool": "create_simulated_transaction",
            "decision": "ALLOW",
            "risk_level": risk_eval.risk_level,
            "result": {
                "transaction_id": txn_id,
                "request_id": request_id or "",
                "from_account": from_account,
                "to_account": to_account,
                "amount": amt,
                "currency": currency,
                "remaining_balance": src["balance"],
                "status": "COMPLETED",
                "real_funds_moved": False
            }
        }


    def schedule_payment(
        self,
        from_account: str,
        to_account: str,
        amount: float,
        execution_date: str,
        customer_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Schedule a future simulated payment."""
        owner_err = self._validate_ownership(customer_id, account_id=from_account)
        if owner_err:
            return owner_err

        if from_account not in self.accounts:
            return {"status": "error", "reason": f"Source account '{from_account}' not found."}

        schedule_id = f"SCHED-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        sched_record = {
            "schedule_id": schedule_id,
            "from_account": from_account,
            "to_account": to_account,
            "amount": amount,
            "execution_date": execution_date,
            "status": "SCHEDULED",
            "created_at": datetime.now().isoformat()
        }
        self.scheduled_payments[schedule_id] = sched_record

        return {
            "status": "success",
            "tool": "schedule_payment",
            "risk_level": "MEDIUM",
            "result": sched_record
        }

    def cancel_payment(self, payment_id: str, customer_id: Optional[str] = None) -> Dict[str, Any]:
        """Cancel a pending scheduled payment."""
        sched = self.scheduled_payments.get(payment_id)
        if not sched:
            return {"status": "error", "reason": f"Scheduled payment '{payment_id}' not found."}

        owner_err = self._validate_ownership(customer_id, account_id=sched["from_account"])
        if owner_err:
            return owner_err

        sched["status"] = "CANCELLED"
        return {
            "status": "success",
            "tool": "cancel_payment",
            "risk_level": "MEDIUM",
            "result": {
                "schedule_id": payment_id,
                "status": "CANCELLED",
                "cancelled_at": datetime.now().isoformat()
            }
        }

    # =========================================================================
    # 3. CARD CATEGORY
    # =========================================================================
    def get_card_status(self, card_id: str, customer_id: Optional[str] = None) -> Dict[str, Any]:
        """Retrieve card status (ACTIVE, FROZEN, EXPIRED)."""
        owner_err = self._validate_ownership(customer_id, card_id=card_id)
        if owner_err:
            return owner_err

        card = self.cards.get(card_id)
        if not card:
            return {"status": "error", "reason": f"Card '{card_id}' not found."}

        return {
            "status": "success",
            "tool": "get_card_status",
            "risk_level": "LOW",
            "result": {
                "card_id": card["card_id"],
                "customer_id": card["customer_id"],
                "card_type": card["card_type"],
                "status": card["status"],
                "last_four": card["last_four"],
                "expiry": card["expiry"]
            }
        }

    def freeze_card(
        self,
        card_id: str,
        customer_id: Optional[str] = None,
        reason: str = "Customer requested card freeze"
    ) -> Dict[str, Any]:
        """Freeze a card (High Risk, Requires Human Approval)."""
        owner_err = self._validate_ownership(customer_id, card_id=card_id)
        if owner_err:
            return owner_err

        card = self.cards.get(card_id)
        if not card:
            return {"status": "error", "reason": f"Card '{card_id}' not found."}

        card["status"] = "FROZEN"
        card["freeze_reason"] = reason
        card["frozen_at"] = datetime.now().isoformat()

        return {
            "status": "success",
            "tool": "freeze_card",
            "risk_level": "HIGH",
            "result": {
                "card_id": card_id,
                "status": "FROZEN",
                "reason": reason,
                "timestamp": card["frozen_at"]
            }
        }

    def unfreeze_card(
        self,
        card_id: str,
        customer_id: Optional[str] = None,
        reason: str = "Customer requested unfreeze"
    ) -> Dict[str, Any]:
        """Unfreeze a card (High Risk, Requires Human Approval)."""
        owner_err = self._validate_ownership(customer_id, card_id=card_id)
        if owner_err:
            return owner_err

        card = self.cards.get(card_id)
        if not card:
            return {"status": "error", "reason": f"Card '{card_id}' not found."}

        card["status"] = "ACTIVE"
        card["unfrozen_at"] = datetime.now().isoformat()

        return {
            "status": "success",
            "tool": "unfreeze_card",
            "risk_level": "HIGH",
            "result": {
                "card_id": card_id,
                "status": "ACTIVE",
                "reason": reason,
                "timestamp": card["unfrozen_at"]
            }
        }

    # =========================================================================
    # 4. FRAUD CATEGORY
    # =========================================================================
    def check_transaction_risk(self, transaction_id: str, amount: Optional[float] = None) -> Dict[str, Any]:
        """Evaluate transaction against deterministic local risk rules via TransactionRiskEngine."""
        amt = amount
        txn = next((t for t in self.transactions if t["transaction_id"] == transaction_id), None)
        if amt is None:
            amt = txn["amount"] if txn else 500.0

        dest = txn["destination_account"] if txn else ""
        src = txn["source_account"] if txn else ""

        risk_res = self.risk_engine.evaluate({
            "transaction_id": transaction_id,
            "amount": amt,
            "source_account": src,
            "destination_account": dest
        })

        return {
            "status": "success",
            "tool": "check_transaction_risk",
            "risk_level": "LOW",
            "result": {
                "transaction_id": transaction_id,
                "evaluated_amount": amt,
                "risk_score": risk_res.risk_score,
                "risk_level": risk_res.risk_level,
                "risk_tier": risk_res.risk_level,
                "decision": risk_res.decision,
                "reasons": risk_res.reasons,
                "risk_factors": risk_res.reasons,
                "recommended_action": risk_res.decision,
                "trace": risk_res.trace
            }
        }

    def flag_transaction(self, transaction_id: str, suspicion_reason: str) -> Dict[str, Any]:
        """Flag transaction for fraud investigation and create case."""
        case_id = f"CASE-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        case_record = {
            "case_id": case_id,
            "transaction_id": transaction_id,
            "status": "UNDER_REVIEW",
            "reason": suspicion_reason,
            "flagged_by": "FRAUD_ANALYST",
            "created_at": datetime.now().isoformat()
        }
        self.fraud_cases[case_id] = case_record

        return {
            "status": "success",
            "tool": "flag_transaction",
            "risk_level": "MEDIUM",
            "result": case_record
        }

    def get_fraud_case(self, case_id: str) -> Dict[str, Any]:
        """Retrieve details of an active fraud case."""
        case = self.fraud_cases.get(case_id)
        if not case:
            return {"status": "error", "reason": f"Fraud case '{case_id}' not found."}

        return {
            "status": "success",
            "tool": "get_fraud_case",
            "risk_level": "LOW",
            "result": case
        }

    # =========================================================================
    # 5. KYC CATEGORY
    # =========================================================================
    def get_kyc_status(self, customer_id: str) -> Dict[str, Any]:
        """Retrieve customer KYC identity status."""
        cust = self.customers.get(customer_id)
        if not cust:
            return {"status": "error", "reason": f"Customer '{customer_id}' not found."}

        return {
            "status": "success",
            "tool": "get_kyc_status",
            "risk_level": "LOW",
            "result": {
                "customer_id": customer_id,
                "kyc_status": cust["kyc_status"],
                "tier": cust["tier"],
                "verified_at": "2026-01-16T10:00:00Z"
            }
        }

    def verify_identity_simulated(
        self,
        customer_id: str,
        document_type: str,
        document_number: str
    ) -> Dict[str, Any]:
        """Simulate identity document verification check."""
        cust = self.customers.get(customer_id)
        if not cust:
            return {"status": "error", "reason": f"Customer '{customer_id}' not found."}

        cust["kyc_status"] = "VERIFIED"
        return {
            "status": "success",
            "tool": "verify_identity_simulated",
            "risk_level": "MEDIUM",
            "result": {
                "customer_id": customer_id,
                "document_type": document_type,
                "document_hash": f"SIM-HASH-{hash(document_number) % 100000:05d}",
                "verification_status": "PASSED",
                "verified_at": datetime.now().isoformat()
            }
        }

    # =========================================================================
    # 6. SUPPORT CATEGORY
    # =========================================================================
    def create_support_ticket(
        self,
        customer_id: str,
        subject: str,
        description: str,
        priority: str = "MEDIUM"
    ) -> Dict[str, Any]:
        """Create a customer support ticket."""
        ticket_id = f"TICK-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        ticket_record = {
            "ticket_id": ticket_id,
            "customer_id": customer_id,
            "subject": subject,
            "description": description,
            "priority": priority,
            "status": "OPEN",
            "created_at": datetime.now().isoformat()
        }
        self.support_tickets[ticket_id] = ticket_record

        return {
            "status": "success",
            "tool": "create_support_ticket",
            "risk_level": "LOW",
            "result": ticket_record
        }

    def send_simulated_notification(
        self,
        customer_id: str,
        message: str,
        channel: str = "EMAIL"
    ) -> Dict[str, Any]:
        """Generate a simulated notification record."""
        notification = {
            "notification_id": f"NOTIF-{len(self.notifications) + 1:04d}",
            "customer_id": customer_id,
            "channel": channel.upper(),
            "message": message,
            "delivered": True,
            "timestamp": datetime.now().isoformat()
        }
        self.notifications.append(notification)

        return {
            "status": "success",
            "tool": "send_simulated_notification",
            "risk_level": "LOW",
            "result": notification
        }
