"""
VulNet FinTech AI Agent Security Lab - Security Audit Logging Subsystem.
Level 2 Step 15: Security Audit and Agent Trace.

Provides:
- Structured audit event records adhering to regulatory compliance
- Invariant: Sensitive secrets (passwords, tokens, keys) are strictly scrubbed
- Disk persistence in append-only JSONL format (`logs/audit.jsonl`)
- Queryable in-memory audit store for fast telemetry retrieval
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
import threading
from typing import Any, Dict, List, Optional

from observability.logger import redact_sensitive_data


@dataclass
class AuditRecord:
    """Structured security audit log record for an operation or request."""
    audit_id: str
    request_id: str
    session_id: str
    user_id: str
    action: str
    decision: str  # "ALLOW", "BLOCK", "REVIEW", "VALIDATE", "ERROR"
    status: str    # "completed", "blocked", "error", "pending"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    agent: Optional[str] = None
    tool: Optional[str] = None
    risk: Optional[str] = "LOW"  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    error: Optional[str] = None
    latency_ms: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        raw = {
            "audit_id": self.audit_id,
            "request_id": self.request_id,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "agent": self.agent,
            "tool": self.tool,
            "action": self.action,
            "risk": self.risk,
            "decision": self.decision,
            "timestamp": self.timestamp,
            "status": self.status,
            "error": self.error,
            "latency_ms": self.latency_ms,
            "metadata": self.metadata,
        }
        return redact_sensitive_data(raw)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


class AuditLogger:
    """
    Thread-safe enterprise audit logger for recording and querying security audit events.
    Appends audit events to JSONL file and maintains a rolling in-memory buffer.
    """

    def __init__(
        self,
        log_file: Optional[Path] = None,
        max_buffer_size: int = 1000
    ):
        self._lock = threading.RLock()
        self._counter = 0
        self._max_buffer = max_buffer_size
        self._buffer: List[AuditRecord] = []

        if log_file is None:
            project_root = Path(__file__).resolve().parent.parent
            self.log_file = project_root / "logs" / "audit.jsonl"
        else:
            self.log_file = Path(log_file)

        # Ensure logs directory exists
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def log_audit(
        self,
        request_id: str,
        session_id: str,
        user_id: str,
        action: str,
        decision: str,
        status: str,
        agent: Optional[str] = None,
        tool: Optional[str] = None,
        risk: Optional[str] = "LOW",
        error: Optional[str] = None,
        latency_ms: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> AuditRecord:
        """Create, persist, and index a sanitized audit record."""
        with self._lock:
            self._counter += 1
            audit_id = f"AUD-{self._counter:06d}"

            # Scrub metadata of sensitive keys
            clean_meta = redact_sensitive_data(metadata or {})

            record = AuditRecord(
                audit_id=audit_id,
                request_id=request_id,
                session_id=session_id,
                user_id=user_id,
                agent=agent,
                tool=tool,
                action=action,
                risk=risk,
                decision=decision,
                timestamp=datetime.now(timezone.utc).isoformat(),
                status=status,
                error=error,
                latency_ms=latency_ms,
                metadata=clean_meta
            )

            # Store in rolling in-memory buffer
            self._buffer.append(record)
            if len(self._buffer) > self._max_buffer:
                self._buffer.pop(0)

            # Persist to disk as JSONL
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(record.to_json() + "\n")
            except Exception:
                # Logging failure should not crash transaction flow
                pass

            return record

    def get_records(self, limit: int = 100) -> List[AuditRecord]:
        """Return the most recent audit records in descending chronological order."""
        with self._lock:
            return list(reversed(self._buffer[-limit:]))

    def get_by_request_id(self, request_id: str) -> List[AuditRecord]:
        """Retrieve all audit events correlated to a specific request ID."""
        with self._lock:
            return [r for r in self._buffer if r.request_id == request_id]

    def clear(self) -> None:
        """Clear the in-memory buffer (primarily for test resets)."""
        with self._lock:
            self._buffer.clear()
            self._counter = 0


_global_audit_logger: Optional[AuditLogger] = None
_audit_lock = threading.Lock()


def get_audit_logger() -> AuditLogger:
    """Retrieve or initialize the global singleton AuditLogger."""
    global _global_audit_logger
    with _audit_lock:
        if _global_audit_logger is None:
            _global_audit_logger = AuditLogger()
        return _global_audit_logger
