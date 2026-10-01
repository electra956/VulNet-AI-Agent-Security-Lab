"""SQL-injection demo: simulated output in Vulnerable Mode, blocked in Secure Mode; nothing is ever executed."""

import sqlite3

import pytest

from fintech.service import get_shared_fintech_service, reset_shared_fintech_service
from security import sql_simulation
from security.security_controller import SecurityController

PAYLOADS = {
    "tautology": "Show transactions for ' OR '1'='1",
    "union": "Show my transactions' UNION SELECT * FROM accounts --",
    "stacked": "Export telemetry dataset; DROP TABLE accounts; --",
    "schema": "list tables from sqlite_master",
}


@pytest.mark.parametrize("kind,payload", PAYLOADS.items())
def test_payload_classified_and_rendered_with_synthetic_rows(kind, payload):
    assert sql_simulation.classify(payload) == kind
    out = sql_simulation.render(payload, "CUST-001", "REQ-1")
    assert "SIMULATED" in out and "no SQL was executed" in out and "Secure Mode" in out


def test_tautology_and_union_return_every_synthetic_account_and_change_nothing():
    reset_shared_fintech_service()
    before = get_shared_fintech_service().get_balance("CUST-001", "ACC-1001")["balance"]
    out = sql_simulation.render(PAYLOADS["union"], "CUST-001")
    assert "ACC-1001" in out and "ACC-2001" in out and "Jordan Lee" in out
    assert get_shared_fintech_service().get_balance("CUST-001", "ACC-1001")["balance"] == before


def test_stacked_drop_is_described_but_never_run(monkeypatch):
    monkeypatch.setattr(sqlite3, "connect", lambda *a, **k: pytest.fail("no database may be opened"))
    out = sql_simulation.render(PAYLOADS["stacked"], "CUST-001")
    assert "DROP" in out and "nothing actually changed" in out


def test_benign_text_is_not_treated_as_injection():
    for text in ("What is my balance?", "Show my last transactions", "Send $25 to ACC-2001", "I'd like to order a drink"):
        assert not sql_simulation.matches(text)


def test_secure_mode_blocks_the_payloads_at_the_perimeter():
    sc = SecurityController(mode="secure")
    for kind, payload in PAYLOADS.items():
        res = sc.evaluate_request(payload)
        assert res["blocked"] is True and "ASI02" in res["scenario"], kind


def test_vulnerable_perimeter_lets_the_payloads_through_as_simulations():
    sc = SecurityController(mode="vulnerable")
    for kind, payload in PAYLOADS.items():
        res = sc.evaluate_request(payload)
        assert res["blocked"] is False and res.get("is_simulation"), kind
