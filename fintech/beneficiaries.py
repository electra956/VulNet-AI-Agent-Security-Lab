"""
Trusted beneficiaries (payees) per customer.

Secure mode only lets money leave a customer's accounts for (a) the customer's own accounts or (b) a payee
the customer has deliberately added here. The list is enforced deterministically in the transaction lifecycle,
outside the LLM, and it can only be changed through the dashboard (Pay page), never through a chat message,
so an injected prompt cannot add an attacker's account.

State lives in a small JSON file (shared by the API and dashboard processes). Override the location with
VULNET_BENEFICIARY_FILE (the test suite points it at a temp dir). Synthetic data only.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from pathlib import Path
from typing import Dict, List

DEFAULT_TRUSTED: Dict[str, List[str]] = {
    "CUST-001": ["ACC-2001"],   # Alex Morgan already pays Jordan Lee
    "CUST-002": ["ACC-1001"],   # Jordan Lee already pays Alex Morgan
}
_ACCT = re.compile(r"^ACC-\d{4,}$")
_LOCK = threading.Lock()


def _path() -> Path:
    env = os.getenv("VULNET_BENEFICIARY_FILE")
    return Path(env) if env else Path(__file__).resolve().parents[1] / "data" / "beneficiaries.json"


class BeneficiaryRegistry:
    def _load(self) -> Dict[str, List[str]]:
        try:
            data = json.loads(_path().read_text(encoding="utf-8"))
            return {k: list(v) for k, v in data.items()}
        except (OSError, ValueError, AttributeError):
            return {k: list(v) for k, v in DEFAULT_TRUSTED.items()}

    def _save(self, data: Dict[str, List[str]]) -> None:
        p = _path()
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=p.parent, suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            os.replace(tmp, p)
        except OSError:
            pass

    def list(self, customer_id: str) -> List[str]:
        return sorted(self._load().get(customer_id, []))

    def is_trusted(self, customer_id: str, account_id: str) -> bool:
        return account_id.strip().upper() in self._load().get(customer_id, [])

    def add(self, customer_id: str, account_id: str) -> bool:
        account_id = account_id.strip().upper()
        if not _ACCT.match(account_id):
            return False
        with _LOCK:
            data = self._load()
            if account_id not in data.setdefault(customer_id, []):
                data[customer_id].append(account_id)
                self._save(data)
        return True

    def remove(self, customer_id: str, account_id: str) -> None:
        with _LOCK:
            data = self._load()
            if account_id.strip().upper() in data.get(customer_id, []):
                data[customer_id].remove(account_id.strip().upper())
                self._save(data)

    def reset(self) -> None:
        with _LOCK:
            self._save({k: list(v) for k, v in DEFAULT_TRUSTED.items()})


_registry = BeneficiaryRegistry()


def get_beneficiary_registry() -> BeneficiaryRegistry:
    return _registry
