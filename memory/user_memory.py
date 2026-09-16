"""
VulNet FinTech AI Agent Security Lab - User Memory
Manages validated long-term user preferences and session context memory.
Enforces the strict invariant: Memory is NEVER an authorization mechanism.
"""

from typing import Any, Dict, List, Optional

from memory.memory_store import MemoryStore
from memory.memory_validator import MemoryValidator, MemoryClassification
from security.security_controller import SecurityController


class UserMemory:
    """
    Manages long-term user preference memory and session context memory.

    Features:
    - Every prospective write is strictly validated via MemoryValidator.
    - Intercepts and blocks all authorization claims ("Remember that I am authorized...").
    - Quarantines and neutralizes memory poisoning attempts (ASI06).
    - Redacts sensitive PII / credential patterns.
    """

    def __init__(
        self,
        memory_store: Optional[MemoryStore] = None,
        validator: Optional[MemoryValidator] = None,
        security_controller: Optional[SecurityController] = None
    ):
        self.security_controller = security_controller or SecurityController(mode="secure")
        self.store = memory_store or MemoryStore(security_controller=self.security_controller)
        self.validator = validator or MemoryValidator()

    def set_preference(
        self,
        user_id: str,
        session_id: str,
        key: str,
        value: Any
    ) -> Dict[str, Any]:
        """
        Store a user preference after strict validation.
        REJECTS authorization claims and malicious injections immediately.
        """
        validation = self.validator.validate_memory(key=key, value=value, memory_type="preference")

        if not validation["is_allowed"] or validation["classification"] == MemoryClassification.REJECTED.value:
            # Telemetry logging for authorization violation / poisoning attempt
            self.security_controller.log_event(
                event_type="MEMORY_WRITE_REJECTED",
                message=f"Memory write rejected: {validation['reason']}",
                severity="HIGH",
                scenario="ASI06 - Memory & Context Poisoning",
                component="USER_MEMORY",
                decision="BLOCK",
                metadata={
                    "user_id": user_id,
                    "session_id": session_id,
                    "key": key,
                    "rejected_pattern": validation.get("rejected_pattern")
                }
            )
            return {
                "success": False,
                "status": "REJECTED",
                "reason": validation["reason"],
                "key": key,
                "classification": MemoryClassification.REJECTED.value
            }

        sanitized_val = validation["sanitized_value"]
        stored_item = self.store.store(
            user_id=user_id,
            session_id=session_id,
            key=key,
            value=sanitized_val,
            memory_type="user_preference",
            classification=validation["classification"],
            metadata={"validation_reason": validation["reason"]}
        )

        return {
            "success": True,
            "status": "STORED",
            "key": key,
            "value": sanitized_val,
            "classification": validation["classification"],
            "item": stored_item
        }

    def get_preference(
        self,
        user_id: str,
        session_id: str,
        key: str,
        default: Optional[Any] = None
    ) -> Any:
        """Retrieve a stored user preference."""
        item = self.store.retrieve(user_id, session_id, key)
        if item:
            return item.get("value", default)
        return default

    def get_all_preferences(
        self,
        user_id: str,
        session_id: str
    ) -> Dict[str, Any]:
        """Retrieve all active preferences in this user session partition."""
        items = self.store.list_memories(user_id, session_id, memory_type="user_preference")
        return {it["key"]: it["value"] for it in items}

    def set_session_context_memory(
        self,
        user_id: str,
        session_id: str,
        context_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Store session context memory after validating each field.
        Guarantees that context cannot be tampered with authorization overrides.
        """
        sanitized_context = {}
        rejected_keys = []

        for k, v in context_data.items():
            val_res = self.validator.validate_memory(key=k, value=v, memory_type="session_context")
            if val_res["is_allowed"]:
                sanitized_context[k] = val_res["sanitized_value"]
            else:
                rejected_keys.append((k, val_res["reason"]))

        self.store.store(
            user_id=user_id,
            session_id=session_id,
            key="_session_context_snapshot",
            value=sanitized_context,
            memory_type="session_context",
            classification="SAFE" if not rejected_keys else "SENSITIVE",
            metadata={"rejected_keys_count": len(rejected_keys)}
        )

        return {
            "success": True,
            "stored_fields": list(sanitized_context.keys()),
            "rejected_fields": rejected_keys
        }

    def get_session_context_memory(
        self,
        user_id: str,
        session_id: str
    ) -> Dict[str, Any]:
        """Retrieve the validated session context snapshot."""
        item = self.store.retrieve(user_id, session_id, "_session_context_snapshot")
        if item and isinstance(item.get("value"), dict):
            return dict(item["value"])
        return {}
