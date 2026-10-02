"""
Persistent chat history for the dashboard, ChatGPT-style: many conversations per user.

Layout: data/chat_history/<user>/<conversation_id>.json. Only synthetic conversation text is stored; nothing
here is a credential. Persistence is a UI-layer feature: library code and tests use in-memory sessions and
never write these files.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_SAFE = re.compile(r"[^A-Za-z0-9_-]")
TITLE_LEN = 48


def _title(messages: List[Dict[str, Any]]) -> str:
    for m in messages:
        if m.get("role") == "user" and str(m.get("content", "")).strip():
            text = " ".join(str(m["content"]).split())
            return text if len(text) <= TITLE_LEN else text[: TITLE_LEN - 1] + "…"
    return "New chat"


class ChatHistoryStore:
    def __init__(self, root: Optional[Path] = None):
        self.root = Path(root) if root else Path(__file__).resolve().parents[2] / "data" / "chat_history"

    def _dir(self, user_id: str) -> Path:
        return self.root / _SAFE.sub("_", user_id)

    def _file(self, user_id: str, conversation_id: str) -> Path:
        return self._dir(user_id) / f"{_SAFE.sub('_', conversation_id)}.json"

    @staticmethod
    def _read(path: Path) -> Optional[Dict[str, Any]]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data.get("messages"), list) else None
        except (OSError, ValueError, AttributeError):
            return None

    def list(self, user_id: str) -> List[Dict[str, Any]]:
        """Conversation summaries, newest first."""
        out = []
        try:
            files = list(self._dir(user_id).glob("*.json"))
        except OSError:
            return []
        for p in files:
            d = self._read(p)
            if d:
                out.append({"conversation_id": d.get("conversation_id", p.stem), "title": d.get("title") or _title(d["messages"]),
                            "updated_at": d.get("updated_at", ""), "count": len(d["messages"])})
        return sorted(out, key=lambda c: c["updated_at"], reverse=True)

    def load(self, user_id: str, conversation_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """One conversation, or the most recently updated one when no id is given."""
        if conversation_id is None:
            latest = self.list(user_id)
            if not latest:
                return None
            conversation_id = latest[0]["conversation_id"]
        return self._read(self._file(user_id, conversation_id))

    def save(self, user_id: str, conversation_id: str, messages: List[Dict[str, Any]]) -> None:
        """Write a conversation; an empty one is removed so blank chats never clutter the history."""
        if not messages:
            self.delete(user_id, conversation_id)
            return
        try:
            d = self._dir(user_id)
            d.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"user_id": user_id, "conversation_id": conversation_id, "title": _title(messages),
                           "updated_at": datetime.now(timezone.utc).isoformat(), "messages": messages}, fh, default=str)
            os.replace(tmp, self._file(user_id, conversation_id))
        except OSError:
            pass                                    # history is a convenience; never break the app over it

    def delete(self, user_id: str, conversation_id: str) -> None:
        try:
            self._file(user_id, conversation_id).unlink()
        except OSError:
            pass

    def clear(self, user_id: str) -> None:
        """Delete every conversation of this user."""
        shutil.rmtree(self._dir(user_id), ignore_errors=True)
