"""
Persistent chat history for the dashboard (one JSON file per user under data/chat_history/).

Only synthetic conversation text is stored; nothing here is a credential. Persistence is a UI-layer feature:
library code and tests use in-memory sessions and never write these files.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

_SAFE = re.compile(r"[^A-Za-z0-9_-]")


class ChatHistoryStore:
    def __init__(self, root: Optional[Path] = None):
        self.root = Path(root) if root else Path(__file__).resolve().parents[2] / "data" / "chat_history"

    def _path(self, user_id: str) -> Path:
        return self.root / f"{_SAFE.sub('_', user_id)}.json"

    def load(self, user_id: str) -> Optional[Dict[str, Any]]:
        try:
            data = json.loads(self._path(user_id).read_text(encoding="utf-8"))
            return data if isinstance(data.get("messages"), list) else None
        except (OSError, ValueError):
            return None

    def save(self, user_id: str, conversation_id: str, messages: List[Dict[str, Any]]) -> None:
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.root, suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"user_id": user_id, "conversation_id": conversation_id, "messages": messages}, fh, default=str)
            os.replace(tmp, self._path(user_id))
        except OSError:
            pass                                    # history is a convenience; never break the app over it

    def clear(self, user_id: str) -> None:
        try:
            self._path(user_id).unlink()
        except OSError:
            pass
