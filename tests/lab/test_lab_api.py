"""Attack Lab API: authentication, mode gating, scenario execution."""

from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


def _session(username="alex_morgan", password="Cust001Secure!2026"):
    lg = client.post("/auth/login", json={"username": username, "password": password}).json()
    return client.post("/auth/mfa/verify", json={"challenge_id": lg["challenge_id"], "code": lg["mfa_code"]}).json()["session_id"]


def test_scenarios_listing_covers_ten_categories():
    r = client.get("/lab/scenarios").json()["scenarios"]
    assert [s["id"] for s in r] == [f"ASI{i:02d}" for i in range(1, 11)]
    assert all(len(s["variants"]) >= 3 for s in r)


def test_run_requires_authentication():
    r = client.post("/lab/run", json={"session_id": "NOPE", "scenario": "ASI01", "variant": "direct", "mode": "secure"})
    assert r.status_code == 401


def test_run_secure_and_vulnerable():
    sid = _session()
    sec = client.post("/lab/run", json={"session_id": sid, "scenario": "ASI01", "variant": "direct", "mode": "secure"}).json()
    assert sec["outcome"] == "ATTACK_BLOCKED" and sec["blocked_by"] and sec["steps"][0]["stage"] == "ATTACK_INPUT"
    vul = client.post("/lab/run", json={"session_id": sid, "scenario": "ASI01", "variant": "direct", "mode": "vulnerable"})
    assert vul.status_code in (200, 403)
    if vul.status_code == 200:
        assert vul.json()["outcome"] == "ATTACK_SUCCEEDED"


def test_bad_inputs_rejected():
    sid = _session()
    assert client.post("/lab/run", json={"session_id": sid, "scenario": "ASI99", "variant": "x"}).status_code == 422
    assert client.post("/lab/run", json={"session_id": sid, "scenario": "ASI01", "variant": "nope"}).status_code == 422
    assert client.post("/lab/run", json={"session_id": sid, "scenario": "ASI01", "variant": "direct", "mode": "evil"}).status_code == 422


def test_test_endpoint_returns_full_record():
    sid = _session()
    rec = client.post("/lab/test", json={"session_id": sid, "scenario": "ASI03", "variant": "cross_customer"}).json()
    for k in ("test_id", "owasp_category", "scenario", "preconditions", "attack_input", "expected_behavior", "actual_behavior",
              "security_control", "evidence", "status", "trace_id", "timestamp"):
        assert k in rec
    assert rec["status"] == "PASS"


def test_catalogues():
    tools = client.get("/lab/tools").json()["tools"]
    names = {t["name"] for t in tools}
    for n in ("get_account_balance", "get_account_status", "get_customer_profile", "get_transaction_history", "get_transaction",
              "create_simulated_transaction", "cancel_simulated_transaction", "create_simulated_payment", "get_payment_status",
              "cancel_simulated_payment", "get_card_status", "freeze_card", "unfreeze_card", "check_transaction_risk",
              "flag_transaction", "get_fraud_case", "get_kyc_status", "verify_identity_simulated", "create_support_ticket",
              "send_simulated_notification"):
        assert n in names, n
    t = next(x for x in tools if x["name"] == "freeze_card")
    for k in ("description", "input_schema", "output_schema", "required_permissions", "risk_level", "owner", "trust_level"):
        assert k in t
    assert len(client.get("/lab/agents").json()["agents"]) >= 7
    rows = client.get("/lab/aibom").json()["components"]
    assert {r["admission"] for r in rows} == {"ADMIT", "REJECT", "QUARANTINE"}


def test_all_synthetic_identities_exist():
    from lab.catalog import users_catalog
    ids = {u["user_id"] for u in users_catalog()}
    assert {"CUST-001", "CUST-002", "SUPPORT-001", "FRAUD-001", "COMPLIANCE-001", "ADMIN-001"} <= ids


def test_oversized_payload_rejected_and_report_is_staff_only():
    cust = _session()
    big = "A" * 25_000
    assert client.post("/lab/run", json={"session_id": cust, "scenario": "ASI05", "variant": "os_command", "mode": "secure", "payload": big}).status_code == 413
    assert client.post("/lab/report", json={"session_id": cust, "scenario": "ASI02"}).status_code == 403
    staff = _session("morgan_vance", "Admin001Secure!2026")
    r = client.post("/lab/report", json={"session_id": staff, "scenario": "ASI02"})
    assert r.status_code == 200 and r.json()["summary"]["total"] == 5
