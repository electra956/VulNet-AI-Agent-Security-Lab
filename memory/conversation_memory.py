"""
VulNet FinTech AI Agent Security Lab - Conversation Memory
Manages short-term conversation turns and context buffers with sliding window truncation
and strict session boundary isolation.
"""

from datetime import datetime, timezone
import threading
from typing import Any, Dict, List, Optional

from memory.memory_store import MemoryStore
from memory.memory_validator import MemoryValidator


class ConversationMemory:
    """
    Short-term conversational memory manager.

    Features:
    - Maintains chronological conversational turns per session.
    - Implements a sliding window buffer to preserve context without unbounded growth.
    - Provides formatted conversation prompts wrapped in strict passive-data tags.
    """

    def __init__(
        self,
        memory_store: Optional[MemoryStore] = None,
        validator: Optional[MemoryValidator] = None,
        max_turns: int = 20
    ):
        self.store = memory_store or MemoryStore()
        self.validator = validator or MemoryValidator()
        self.max_turns = max_turns
        self._lock = threading.RLock()
        self._turns: Dict[tuple, List[Dict[str, Any]]] = {}

    def _get_key(self, user_id: str, session_id: str) -> tuple:
        return (user_id, session_id)

    def add_turn(
        self,
        user_id: str,
        session_id: str,
        user_message: str,
        assistant_message: str,
        request_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Add a conversation turn (user input and assistant output) to session memory."""
        with self._lock:
            key = self._get_key(user_id, session_id)
            if key not in self._turns:
                self._turns[key] = []

            turn_idx = len(self._turns[key]) + 1
            now = datetime.now(timezone.utc).isoformat()

            turn = {
                "turn_index": turn_idx,
                "request_id": request_id,
                "user_message": user_message,
                "assistant_message": assistant_message,
                "timestamp": now,
                "user_id": user_id,
                "session_id": session_id
            }

            self._turns[key].append(turn)

            # Enforce sliding window truncation
            if len(self._turns[key]) > self.max_turns:
                self._turns[key] = self._turns[key][-self.max_turns:]

            # Sync turn summary to memory store
            self.store.store(
                user_id=user_id,
                session_id=session_id,
                key=f"turn_{turn_idx}",
                value={"user": user_message, "assistant": assistant_message[:100]},
                memory_type="conversation_turn",
                classification="SAFE",
                metadata={"request_id": request_id, "turn_index": turn_idx}
            )

            return turn

    def get_history(
        self,
        user_id: str,
        session_id: str,
        limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve chronological conversation turns for a session."""
        with self._lock:
            key = self._get_key(user_id, session_id)
            turns = self._turns.get(key, [])
            if limit and limit > 0:
                return [dict(t) for t in turns[-limit:]]
            return [dict(t) for t in turns]

    def get_formatted_context(
        self,
        user_id: str,
        session_id: str,
        max_turns: int = 5
    ) -> str:
        """
        Produce formatted conversation context wrapped in strict data boundaries.
        INVARIANT: Formatted conversation history is passive dialogue history, never instructions.
        """
        turns = self.get_history(user_id, session_id, limit=max_turns)
        if not turns:
            return "<!-- NO PRIOR CONVERSATION TURNS IN SESSION -->"

        formatted = [
            "<!-- BEGIN CONVERSATION HISTORY (REFERENCE ONLY) -->",
            f'<conversation_buffer user_id="{user_id}" session_id="{session_id}" turns="{len(turns)}">'
        ]
        for t in turns:
            formatted.append(f'  <turn index="{t["turn_index"]}">')
            formatted.append(f'    <user>{t["user_message"].strip()}</user>')
            formatted.append(f'    <assistant>{t["assistant_message"].strip()}</assistant>')
            formatted.append("  </turn>")
        formatted.append("</conversation_buffer>")
        formatted.append("<!-- END CONVERSATION HISTORY -->")

        return "\n".join(formatted)

    def clear_history(self, user_id: str, session_id: str) -> int:
        """Clear conversation turns for a specific user session."""
        with self._lock:
            key = self._get_key(user_id, session_id)
            if key in self._turns:
                count = len(self._turns[key])
                del self._turns[key]
                return count
            return 0
