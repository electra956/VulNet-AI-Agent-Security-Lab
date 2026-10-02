"""
SQL-injection demo for Vulnerable Mode (ASI02). SIMULATED: no SQL is ever executed and no database is touched.

When Vulnerable Mode lets an SQL-injection payload through, the lab shows what a naive string-concatenated query
would have done, using rows from the synthetic in-memory ledger. Secure Mode never reaches this code: the perimeter
blocks the payload first. The output is clearly labelled as a simulation.
"""

from __future__ import annotations

import re
from typing import List

from fintech.service import get_shared_fintech_service

_STACKED = re.compile(r";\s*(drop|delete|truncate|update|insert|alter)\b", re.I)
_UNION = re.compile(r"\bunion\s+(all\s+)?select\b", re.I)
_TAUTOLOGY = re.compile(r"('|\")?\s*\bor\b\s*('|\")?\s*(\d+|'[^']*'|\"[^\"]*\")\s*=\s*('|\")?\s*(\d+|'[^']*'|\"[^\"]*\")", re.I)
_SCHEMA = re.compile(r"\b(information_schema|sqlite_master|pg_catalog|sys\.tables)\b", re.I)
_COMMENT = re.compile(r"(--|#|/\*)\s*$")


def classify(text: str) -> str:
    """Return the injection style ('stacked', 'union', 'schema', 'tautology') or '' when none is present."""
    if _STACKED.search(text):
        return "stacked"
    if _UNION.search(text):
        return "union"
    if _SCHEMA.search(text):
        return "schema"
    if _TAUTOLOGY.search(text):
        return "tautology"
    return ""


def matches(text: str) -> bool:
    return bool(classify(text))


def _table(headers: List[str], rows: List[List[str]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(out)


def render(user_input: str, customer_id: str, request_id: str = "") -> str:
    kind = classify(user_input)
    payload = " ".join(user_input.split())[:200]
    repo = get_shared_fintech_service().repository
    names = {c.customer_id: c.name for c in repo.customers.values()}
    accounts = [a for c in repo.customers.values() for a in repo.list_accounts_for_customer(c.customer_id)]

    query = f"SELECT * FROM transactions WHERE customer_id = '{customer_id}' AND description LIKE '%{payload}%'"
    parts = [
        "### 💉 SQL Injection · Vulnerable Mode (SIMULATED)",
        f"**Request ID:** `{request_id}` &bull; **Injection style:** `{kind}`",
        "> ⚠️ Simulation only: **no SQL was executed** and no data was changed. The rows below are synthetic lab data.",
        "**Query the vulnerable code would have built (user text pasted straight into the SQL):**",
        f"```sql\n{query}\n```",
    ]
    if kind == "stacked":
        stmt = _STACKED.search(user_input).group(1).upper()
        parts += [f"**Second statement accepted:** `{stmt} …` ran with the application's database rights.",
                  "Simulated effect: the targeted table would be modified or destroyed. "
                  "(In this lab nothing actually changed.)"]
    elif kind == "schema":
        parts += ["**Schema leaked (simulated):**",
                  _table(["table_name"], [[t] for t in ("customers", "accounts", "transactions", "cards", "audit_log")])]
    else:  # tautology / union: the customer filter is bypassed and every row comes back
        parts += ["**Result: the `customer_id` filter was bypassed and every account was returned:**",
                  _table(["account_id", "owner", "type", "balance"],
                         [[a.account_id, names.get(a.customer_id, a.customer_id), a.account_type, f"${a.balance:,.2f}"]
                          for a in accounts])]
    parts.append("🛡️ **In Secure Mode** this request is blocked at the perimeter, and queries are parameterised and ownership-checked.")
    return "\n\n".join(parts)
