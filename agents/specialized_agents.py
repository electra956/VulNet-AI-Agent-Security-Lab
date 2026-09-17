"""
VulNet FinTech AI Agent Security Lab - Specialized FinTech Agents
Dedicated, domain-focused agents operating under the control of the Agent Orchestrator:
- CustomerAgent
- FinancialResearchAgent
- TransactionAgent
- FraudAgent
- ComplianceAgent
- SupportAgent

INVARIANT:
- Agents return structured output dictionaries.
- Agents do NOT execute real financial actions or real infrastructure changes.
- The Main Agent does not directly execute tools; the Orchestrator coordinates execution.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import re


class BaseFinTechAgent(ABC):
    """Abstract base class for all specialized FinTech agents."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the specialized agent."""
        pass

    @abstractmethod
    def process(
        self,
        request: str,
        plan: Dict[str, Any],
        session_context: Optional[Dict[str, Any]] = None,
        retrieved_documents: Optional[List[Any]] = None,
        mode: str = "secure"
    ) -> Dict[str, Any]:
        """
        Execute specialized agent logic and return a structured agent output contract:
        {
            "agent": str,
            "intent": str,
            "status": "completed" | "requires_tool" | "requires_approval" | "rejected" | "invalid_request",
            "requested_action": str,
            "response": str,
            "metadata": dict
        }
        """
        pass


class CustomerAgent(BaseFinTechAgent):
    """
    Handles customer profiles, accounts, balances, and customer preferences.
    Example: "What is my balance?" -> CustomerAgent
    """

    @property
    def name(self) -> str:
        return "CustomerAgent"

    def process(
        self,
        request: str,
        plan: Dict[str, Any],
        session_context: Optional[Dict[str, Any]] = None,
        retrieved_documents: Optional[List[Any]] = None,
        mode: str = "secure"
    ) -> Dict[str, Any]:
        intent = plan.get("intent", "BALANCE_INQUIRY")
        user_id = (session_context or {}).get("user_id", "CUST-001")
        accounts = (session_context or {}).get("account_ids", ["ACC-1001"])
        primary_account = accounts[0] if accounts else "ACC-1001"

        # Check if the query asks for balance or profile info
        if "balance" in request.lower():
            requested_action = "get_balance"
            response_text = (
                f"### 💳 Customer Account Overview\n\n"
                f"- **Customer ID:** `{user_id}`\n"
                f"- **Primary Account:** `{primary_account}`\n"
                f"- **Available Accounts:** {', '.join(f'`{acc}`' for acc in accounts)}\n\n"
                f"Your balance inquiry has been retrieved from the customer domain service."
            )
        else:
            requested_action = "get_customer_profile"
            response_text = (
                f"### 👤 Customer Profile Summary\n\n"
                f"- **Customer ID:** `{user_id}`\n"
                f"- **Registered Accounts:** {', '.join(f'`{acc}`' for acc in accounts)}\n"
                f"- **Relationship Status:** Active Customer"
            )

        return {
            "agent": self.name,
            "intent": intent,
            "status": "completed",
            "requested_action": requested_action,
            "response": response_text,
            "metadata": {
                "customer_id": user_id,
                "primary_account": primary_account,
                "account_count": len(accounts)
            }
        }


class FinancialResearchAgent(BaseFinTechAgent):
    """
    Handles financial knowledge, market information, policy documentation,
    and product comparisons using local RAG context.
    Example: "What are the KYC requirements?" -> FinancialResearchAgent
    """

    @property
    def name(self) -> str:
        return "FinancialResearchAgent"

    def process(
        self,
        request: str,
        plan: Dict[str, Any],
        session_context: Optional[Dict[str, Any]] = None,
        retrieved_documents: Optional[List[Any]] = None,
        mode: str = "secure"
    ) -> Dict[str, Any]:
        intent = plan.get("intent", "FINANCIAL_RESEARCH")
        docs = retrieved_documents or []
        doc_count = len(docs)

        doc_previews = []
        for doc in docs:
            if isinstance(doc, dict):
                d_name = doc.get("filename", doc.get("document", "Knowledge Document"))
                score = doc.get("score", 0.0)
                doc_previews.append(f"- 📄 `{d_name}` (Relevance: {score:.3f})")
            else:
                doc_previews.append(f"- 📄 `{str(doc)}`")

        preview_str = "\n".join(doc_previews) if doc_previews else "No local policy documents matched the query."

        response_text = (
            f"### 📚 Financial Research Findings\n\n"
            f"**Research Topic:** `{request}`\n\n"
            f"**Retrieved Sources:** {doc_count} source(s)\n\n"
            f"{preview_str}\n\n"
            f"> All financial research findings are derived from local verified knowledge bases."
        )

        return {
            "agent": self.name,
            "intent": intent,
            "status": "completed",
            "requested_action": "search_knowledge_base",
            "response": response_text,
            "metadata": {
                "documents_used": doc_count,
                "knowledge_source": "Local RAG Engine"
            }
        }


class TransactionAgent(BaseFinTechAgent):
    """
    Handles payment proposals, fund transfer requests, and transaction histories.
    Example: "Transfer ₹5,000" or "Send $50 to Bob" -> TransactionAgent

    INVARIANT: Does NOT execute real financial actions. Returns "requires_tool"
    or "requires_approval" to maintain strict payment safety.
    """

    @property
    def name(self) -> str:
        return "TransactionAgent"

    def process(
        self,
        request: str,
        plan: Dict[str, Any],
        session_context: Optional[Dict[str, Any]] = None,
        retrieved_documents: Optional[List[Any]] = None,
        mode: str = "secure"
    ) -> Dict[str, Any]:
        intent = plan.get("intent", "PAYMENT_REQUEST")
        user_id = (session_context or {}).get("user_id", "CUST-001")
        accounts = (session_context or {}).get("account_ids", ["ACC-1001"])

        # Parse amount and currency
        amount_match = re.search(r"(\$|₹|USD|INR|EUR|rs\.?)?\s*([0-9]+(?:,[0-9]{3})*(?:\.[0-9]{2})?)", request, re.IGNORECASE)
        currency = "$"
        amount_str = "0.00"
        amount_val = 0.0

        if amount_match:
            curr_symbol = (amount_match.group(1) or "$").lower()
            currency = "₹" if "₹" in curr_symbol or "inr" in request.lower() or "rs" in curr_symbol else "$"
            amount_str = amount_match.group(2).replace(",", "")
            try:
                amount_val = float(amount_str)
            except ValueError:
                amount_val = 0.0

        # Parse accounts
        acct_from_match = re.search(r"from\s+(ACC-\d{4})", request, re.IGNORECASE)
        acct_to_match = re.search(r"to\s+(ACC-\d{4})", request, re.IGNORECASE)
        all_accts = re.findall(r"\b(ACC-\d{4})\b", request, re.IGNORECASE)

        source_account = accounts[0] if accounts else "ACC-1001"
        destination_account = "ACC-2001" if source_account != "ACC-2001" else "ACC-1002"

        if acct_from_match:
            source_account = acct_from_match.group(1).upper()
        elif len(all_accts) >= 1 and not acct_to_match:
            source_account = all_accts[0].upper()

        if acct_to_match:
            destination_account = acct_to_match.group(1).upper()
        elif len(all_accts) >= 2 and not acct_from_match:
            source_account = all_accts[0].upper()
            destination_account = all_accts[1].upper()
        elif len(all_accts) == 1 and acct_to_match:
            source_account = accounts[0] if accounts else "ACC-1001"

        # Check for transfer / payment vs history lookup
        if any(w in request.lower() for w in ["transfer", "send", "pay", "wire"]):
            requested_action = "create_payment"
            # High-value transfer threshold: >= 10,000 requires human approval
            if amount_val >= 10000:
                status = "requires_approval"
                status_desc = "⚠️ Approval Required (High-Value Transfer Policy Enforced)"
            else:
                status = "requires_tool"
                status_desc = "⚡ Pending Tool Execution (Simulated Payment Proposal Formulated)"

            response_text = (
                f"### 💸 Transaction Formulation Proposal\n\n"
                f"- **Originator:** `{user_id}`\n"
                f"- **Source Account:** `{source_account}`\n"
                f"- **Destination Account:** `{destination_account}`\n"
                f"- **Proposed Amount:** `{currency}{amount_val:,.2f}`\n"
                f"- **Operational Status:** {status_desc}\n\n"
                f"> **Safety Invariant:** No real financial execution was triggered. "
                f"This simulated transaction proposal requires explicit tool validation."
            )
        else:
            requested_action = "get_transaction_history"
            status = "completed"
            response_text = (
                f"### 📋 Transaction History Query\n\n"
                f"- **Account:** `{source_account}`\n"
                f"- **Customer:** `{user_id}`\n\n"
                f"Transaction records have been retrieved from the ledger."
            )

        return {
            "agent": self.name,
            "intent": intent,
            "status": status,
            "requested_action": requested_action,
            "response": response_text,
            "metadata": {
                "source_account": source_account,
                "destination_account": destination_account,
                "amount": amount_val,
                "currency": currency,
                "is_real_execution": False
            }
        }



class FraudAgent(BaseFinTechAgent):
    """
    Handles fraud inquiries, flagged transaction investigations, and dispute reviews.
    Example: "Why was my transaction flagged?" -> FraudAgent
    """

    @property
    def name(self) -> str:
        return "FraudAgent"

    def process(
        self,
        request: str,
        plan: Dict[str, Any],
        session_context: Optional[Dict[str, Any]] = None,
        retrieved_documents: Optional[List[Any]] = None,
        mode: str = "secure"
    ) -> Dict[str, Any]:
        intent = plan.get("intent", "FRAUD_DISPUTE")
        user_id = (session_context or {}).get("user_id", "CUST-001")

        response_text = (
            f"### 🛡️ Fraud & Risk Operations Review\n\n"
            f"**Inquiry:** `{request}`\n\n"
            f"- **Customer:** `{user_id}`\n"
            f"- **Investigation Status:** `UNDER_REVIEW`\n"
            f"- **Risk Classification:** `SUSPICIOUS_ACTIVITY_EVALUATION`\n\n"
            f"**Automated Risk Findings:**\n"
            f"- The transaction was flagged by automated anomaly heuristics (e.g., velocity check, geographic mismatch, or uncharacteristic transaction volume).\n"
            f"- A risk analyst ticket has been registered in the fraud review queue.\n"
            f"- No unauthorized funds were transferred."
        )

        return {
            "agent": self.name,
            "intent": intent,
            "status": "completed",
            "requested_action": "review_flagged_transaction",
            "response": response_text,
            "metadata": {
                "customer_id": user_id,
                "review_tier": "TIER_2_FRAUD_ANALYST",
                "dispute_eligible": True
            }
        }


class ComplianceAgent(BaseFinTechAgent):
    """
    Handles regulatory compliance, KYC requirements, and AML policies.
    Example: "What are the KYC requirements?" -> ComplianceAgent
    """

    @property
    def name(self) -> str:
        return "ComplianceAgent"

    def process(
        self,
        request: str,
        plan: Dict[str, Any],
        session_context: Optional[Dict[str, Any]] = None,
        retrieved_documents: Optional[List[Any]] = None,
        mode: str = "secure"
    ) -> Dict[str, Any]:
        intent = plan.get("intent", "COMPLIANCE_INQUIRY")
        user_id = (session_context or {}).get("user_id", "CUST-001")

        response_text = (
            f"### ⚖️ Regulatory & KYC Compliance Advisory\n\n"
            f"**Topic:** `{request}`\n\n"
            f"**Standard KYC & Verification Requirements:**\n"
            f"1. **Government-Issued Photo ID**: Valid Passport, Driver's License, or National ID card.\n"
            f"2. **Proof of Physical Address**: Utility bill or bank statement dated within the last 90 days.\n"
            f"3. **Taxpayer Identification**: SSN / ITIN / PAN / National Tax Number.\n"
            f"4. **Beneficial Ownership Verification**: For corporate entities, disclosure of all $\\ge 25\\%$ equity holders.\n\n"
            f"> **Regulatory Notice:** All documents are processed according to simulated FinTech BSA/AML compliance standards."
        )

        return {
            "agent": self.name,
            "intent": intent,
            "status": "completed",
            "requested_action": "get_kyc_requirements",
            "response": response_text,
            "metadata": {
                "customer_id": user_id,
                "jurisdiction": "Simulated US/Global FinTech",
                "framework": "BSA/AML/KYC"
            }
        }


class SupportAgent(BaseFinTechAgent):
    """
    Handles general customer support, card freeze requests, and ticket creation.
    Example: "Help with my account" or "I want to freeze my debit card" -> SupportAgent
    """

    @property
    def name(self) -> str:
        return "SupportAgent"

    def process(
        self,
        request: str,
        plan: Dict[str, Any],
        session_context: Optional[Dict[str, Any]] = None,
        retrieved_documents: Optional[List[Any]] = None,
        mode: str = "secure"
    ) -> Dict[str, Any]:
        intent = plan.get("intent", "SUPPORT_REQUEST")
        user_id = (session_context or {}).get("user_id", "CUST-001")

        if any(w in request.lower() for w in ["freeze", "block card", "lost card"]):
            requested_action = "freeze_card"
            action_summary = "Card freeze request simulated. Your card is temporarily suspended from new charges."
        else:
            requested_action = "create_support_ticket"
            action_summary = "Support ticket generated. A simulated representative will follow up."

        response_text = (
            f"### 🎧 Customer Support Services\n\n"
            f"**User Request:** `{request}`\n\n"
            f"- **Customer:** `{user_id}`\n"
            f"- **Action Taken:** {action_summary}\n"
            f"- **Support Status:** Active Ticket Created\n\n"
            f"How else can we assist your banking experience?"
        )

        return {
            "agent": self.name,
            "intent": intent,
            "status": "completed",
            "requested_action": requested_action,
            "response": response_text,
            "metadata": {
                "customer_id": user_id,
                "ticket_priority": "NORMAL",
                "channel": "CHATBOT"
            }
        }
