"""
VulNet FinTech AI Agent Security Lab - Memory Store
Thread-safe, partitioned in-memory storage engine for agent conversation,
preferences, and session context with strict session isolation.
"""

from datetime import datetime, timezone
import threading
from typing import Any, Dict, List, Optional, Tuple

from security.security_controller import SecurityController


class MemoryStore:
    """
    Central in-memory store for VulNet AI Agent memories.

    Features:
    - Partitioned strictly by (user_id, session_id) ensuring no cross-session or cross-user leakage.
    - Tracks memory classifications (SAFE, SENSITIVE, UNTRUSTED, REJECTED).
    - Logs telemetry events via SecurityController for audit trails and threat visibility.
    """

    def __init__(self, security_controller: Optional[SecurityController] = None):
        self._lock = threading.RLock()
        self._store: Dict[Tuple[str, str], Dict[str, Dict[str, Any]]] = {}
        self.security_controller = security_controller or SecurityController(mode="secure")

    def _get_partition(self, user_id: str, session_id: str) -> Dict[str, Dict[str, Any]]:
        key = (user_id, session_id)
        if key not in self._store:
            self._store[key] = {}
        return self._store[key]

    def store(
        self,
        user_id: str,
        session_id: str,
        key: str,
        value: Any,
        memory_type: str = "preference",
        classification: str = "SAFE",
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Store or update a validated memory item in the isolated partition."""
        with self._lock:
            partition = self._get_partition(user_id, session_id)
            now = datetime.now(timezone.utc).isoformat()

            item = {
                "key": key,
                "value": value,
                "memory_type": memory_type,
                "classification": classification,
                "user_id": user_id,
                "session_id": session_id,
                "created_at": partition.get(key, {}).get("created_at", now),
                "updated_at": now,
                "access_count": partition.get(key, {}).get("access_count", 0),
                "metadata": metadata or {}
            }
            partition[key] = item

            # Audit logging for security telemetry
            self.security_controller.log_event(
                event_type="MEMORY_ITEM_STORED",
                message=f"Memory item '{key}' [{classification}] persisted for user '{user_id}'.",
                severity="INFO" if classification == "SAFE" else "WARNING",
                scenario=None,
                component="MEMORY_STORE",
                decision="ALLOW",
                metadata={"user_id": user_id, "session_id": session_id, "key": key, "classification": classification}
            )

            return item

    def retrieve(
        self,
        user_id: str,
        session_id: str,
        key: str
    ) -> Optional[Dict[str, Any]]:
        """Retrieve a memory item from the isolated partition."""
        with self._lock:
            partition = self._get_partition(user_id, session_id)
            item = partition.get(key)
            if item:
                item["access_count"] += 1
                return dict(item)
            return None

    def list_memories(
        self,
        user_id: str,
        session_id: str,
        memory_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List all memories within a specific user session partition."""
        with self._lock:
            partition = self._get_partition(user_id, session_id)
            items = list(partition.values())
            if memory_type:
                items = [it for it in items if it.get("memory_type") == memory_type]
            return [dict(it) for it in items]

    def delete_memory(
        self,
        user_id: str,
        session_id: str,
        key: str
    ) -> bool:
        """Delete a memory item from a partition."""
        with self._lock:
            partition = self._get_partition(user_id, session_id)
            if key in partition:
                del partition[key]
                return True
            return False

    def clear_session(self, user_id: str, session_id: str) -> int:
        """Clear all memories associated with a specific user session."""
        with self._lock:
            key = (user_id, session_id)
            if key in self._store:
                count = len(self._store[key])
                del self._store[key]
                return count
            return 0

    def clear_all(self) -> None:
        """Reset the entire memory store (used in testing)."""
        with self._lock:
            self._store.clear()
