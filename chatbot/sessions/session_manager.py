"""
VulNet FinTech AI Agent Security Lab - Session Management & Structured Context.
Level 2 Step 3: Proper Chat Session Context.

Provides:
- Strongly typed SessionContext carrying request_id, session_id, user_id, role,
  account_ids, created_at, and conversation_id.
- Complete session isolation (isolated state, history, and telemetry per session).
- Monotonic request correlation and sequential audit tracking.
- Synthetic customer context for local simulation.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
import itertools
from typing import Any, Dict, List, Optional
import uuid


@dataclass
class SessionContext:
    """
    Structured request context carried through every layer of the application.
    Correlates requests, sessions, authenticated identities, and conversation threads.
    """
    session_id: str
    request_id: str
    user_id: str
    role: str
    account_ids: List[str]
    created_at: str
    conversation_id: str

    def to_dict(self) -> Dict[str, Any]:
        """Return context as a serializable dictionary."""
        return asdict(self)


@dataclass
class CustomerContext:
    """
    Simulated customer context representing an authenticated banking customer.
    All data is purely synthetic with zero real-world connection.
    """
    customer_id: str = "CUST-001"
    account_id: str = "ACC-1001"
    account_ids: List[str] = field(default_factory=lambda: ["ACC-1001", "ACC-1002"])
    user_role: str = "customer"
    full_name: str = "Alex Morgan (Synthetic)"
    account_type: str = "Premier Checking (Simulated)"
    balance: float = 5420.50
    currency: str = "USD"
    status: str = "ACTIVE"
    kyc_status: str = "VERIFIED"
    tier: str = "Retail Standard"
    created_at: str = "2026-01-15T09:00:00Z"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SyntheticTransaction:
    """Simulated account transaction for FinTech display."""
    transaction_id: str
    timestamp: str
    description: str
    amount: float
    transaction_type: str  # DEBIT, CREDIT, TRANSFER
    status: str            # COMPLETED, PENDING, BLOCKED
    reference: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def get_default_synthetic_transactions(account_id: str = "ACC-1001") -> List[SyntheticTransaction]:
    """Return realistic mock banking transactions for backward compatibility."""
    return [
        SyntheticTransaction(
            transaction_id="TXN-98401",
            timestamp="2026-09-16T08:14:22Z",
            description="Payroll Direct Deposit - Acme Corp",
            amount=3200.00,
            transaction_type="CREDIT",
            status="COMPLETED",
            reference="ACH-REF-8921"
        ),
        SyntheticTransaction(
            transaction_id="TXN-98402",
            timestamp="2026-09-15T18:45:10Z",
            description="Coffee Bean - Point of Sale",
            amount=-5.75,
            transaction_type="DEBIT",
            status="COMPLETED",
            reference="POS-AUTH-4412"
        ),
        SyntheticTransaction(
            transaction_id="TXN-98403",
            timestamp="2026-09-14T11:20:05Z",
            description="Metro Electric Utility Bill",
            amount=-142.50,
            transaction_type="DEBIT",
            status="COMPLETED",
            reference="BILL-PAY-0922"
        ),
        SyntheticTransaction(
            transaction_id="TXN-98404",
            timestamp="2026-09-12T14:32:00Z",
            description="ATM Cash Withdrawal (Branch #04)",
            amount=-80.00,
            transaction_type="DEBIT",
            status="COMPLETED",
            reference="ATM-WTH-1099"
        ),
        SyntheticTransaction(
            transaction_id="TXN-98405",
            timestamp="2026-09-10T09:15:30Z",
            description="Inbound Wire Transfer - Family Member",
            amount=450.00,
            transaction_type="CREDIT",
            status="COMPLETED",
            reference="WIRE-IN-3321"
        ),
    ]


@dataclass
class ChatMessage:
    """Standardized chat message within a FinTech session."""
    role: str
    content: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class Session:
    """
    Encapsulates an isolated user session for the VulNet FinTech AI Agent.
    
    Contains:
    - session_id
    - user_id
    - created_at
    - conversation_id
    - messages (isolated list)
    - security_events (isolated list)
    - customer_context (isolated context)
    """

    def __init__(
        self,
        session_id: str,
        user_id: str = "CUST-001",
        customer_context: Optional[CustomerContext] = None,
        conversation_id: Optional[str] = None,
        created_at: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.session_id = session_id
        self.user_id = user_id
        self.conversation_id = conversation_id or f"CONV-{uuid.uuid4().hex[:8].upper()}"
        self.created_at = created_at or datetime.now().isoformat()
        self.customer_context = customer_context or CustomerContext(customer_id=user_id)
        self.messages: List[Dict[str, Any]] = []
        self.security_events: List[Dict[str, Any]] = []
        self.metadata: Dict[str, Any] = metadata or {}

    def create_request_context(self, request_id: Optional[str] = None) -> SessionContext:
        """
        Create a structured request context carrying this session's identity
        and customer authorization attributes.
        """
        req_id = request_id or SessionManager.generate_request_id()
        account_ids = (
            list(self.customer_context.account_ids)
            if hasattr(self.customer_context, "account_ids") and self.customer_context.account_ids
            else [self.customer_context.account_id]
        )
        return SessionContext(
            session_id=self.session_id,
            request_id=req_id,
            user_id=self.user_id,
            role=self.customer_context.user_role,
            account_ids=account_ids,
            created_at=datetime.now().isoformat(),
            conversation_id=self.conversation_id
        )

    def add_message(
        self,
        role: str,
        content: str,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Add a message record isolated to this session."""
        msg = ChatMessage(
            role=role,
            content=content,
            request_id=request_id,
            session_id=self.session_id,
            metadata=metadata or {}
        ).to_dict()
        self.messages.append(msg)
        return msg

    def add_security_event(self, event: Dict[str, Any]) -> None:
        """Log a security event isolated to this session."""
        event_record = dict(event)
        event_record["session_id"] = self.session_id
        self.security_events.append(event_record)

    def get_messages(self) -> List[Dict[str, Any]]:
        """Return isolated copy of messages."""
        return list(self.messages)

    def get_security_events(self) -> List[Dict[str, Any]]:
        """Return isolated copy of recorded security events."""
        return list(self.security_events)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "conversation_id": self.conversation_id,
            "created_at": self.created_at,
            "message_count": len(self.messages),
            "security_event_count": len(self.security_events),
            "customer_context": self.customer_context.to_dict(),
            "metadata": self.metadata
        }


class SessionManager:
    """
    Thread-safe manager for isolated FinTech chat sessions.
    Guarantees that session state, history, and telemetry cannot leak across sessions.
    """
    _counter = itertools.count(1)
    _session_counter = itertools.count(1)

    def __init__(self):
        self._sessions: Dict[str, Session] = {}
        self._active_session_id: Optional[str] = None

    @classmethod
    def generate_request_id(cls) -> str:
        """
        Generate a monotonically increasing request ID:
        e.g. REQ-000001, REQ-000002.
        """
        count = next(cls._counter)
        return f"REQ-{count:06d}"

    @classmethod
    def generate_session_id(cls) -> str:
        """Generate a clean sequential session ID (e.g. SESSION-001)."""
        count = next(cls._session_counter)
        return f"SESSION-{count:03d}"

    def create_session(
        self,
        user_id: str = "CUST-001",
        customer_context: Optional[CustomerContext] = None,
        session_id: Optional[str] = None,
        conversation_id: Optional[str] = None
    ) -> Session:
        """Create, isolate, and store a new active session."""
        if not session_id:
            session_id = self.generate_session_id()

        context = customer_context or CustomerContext(customer_id=user_id)
        session = Session(
            session_id=session_id,
            user_id=user_id,
            customer_context=context,
            conversation_id=conversation_id
        )
        self._sessions[session_id] = session
        self._active_session_id = session_id
        return session

    def get_session(self, session_id: str) -> Optional[Session]:
        """
        Retrieve a session strictly by its ID.
        Returns None if session does not exist, preserving session isolation.
        """
        return self._sessions.get(session_id)

    def get_or_create_active_session(
        self,
        user_id: str = "CUST-001",
        customer_context: Optional[CustomerContext] = None
    ) -> Session:
        """Get the current active session, or create one if none exists."""
        if self._active_session_id and self._active_session_id in self._sessions:
            return self._sessions[self._active_session_id]
        return self.create_session(user_id=user_id, customer_context=customer_context)

    def set_active_session(self, session_id: str) -> bool:
        """Switch active session."""
        if session_id in self._sessions:
            self._active_session_id = session_id
            return True
        return False

    def list_sessions(self) -> List[Session]:
        """List all active sessions."""
        return list(self._sessions.values())

    def clear(self) -> None:
        """Clear all sessions (useful for test resets)."""
        self._sessions.clear()
        self._active_session_id = None


_shared_session_manager: Optional[SessionManager] = None


def get_shared_session_manager() -> SessionManager:
    """Retrieve or create the shared SessionManager singleton."""
    global _shared_session_manager
    if _shared_session_manager is None:
        _shared_session_manager = SessionManager()
    return _shared_session_manager
