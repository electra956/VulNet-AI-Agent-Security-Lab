"""Deterministic controls: goal guard, rate limit, identity, circuit breaker, supervisor, gateway."""

import copy

import pytest

from lab.controls import (AgentSupervisor, CircuitBreaker, GoalGuard, IdentityAuthority, ToolRateLimiter, classify_goal)
from lab.core import AttackTrace, CUSTOMER_001, LabEnvironment, ToolGateway, classify_risk


def _gw(mode="secure", **kw):
    env = LabEnvironment(mode)
    tr = AttackTrace("T", mode)
    ident = IdentityAuthority.issue(copy.deepcopy(CUSTOMER_001)) if mode == "secure" else copy.deepcopy(CUSTOMER_001)
    return env, tr, ident, ToolGateway(env, tr, mode, **kw)


def test_goal_comes_from_user_message_only():
    assert classify_goal("Summarise the KYC policy update.") == "knowledge_question"
    assert classify_goal("Transfer 100 to ACC-1002") == "transfer"
    g = GoalGuard("Summarise the KYC policy update.")
    assert g.permits("search_knowledge_base")[0]
    ok, why = g.permits("create_simulated_transaction")
    assert not ok and "Goal drift" in why


def test_rate_limiter():
    rl = ToolRateLimiter(max_calls_per_tool=2, max_calls_total=10)
    assert [rl.allow("A", "t")[0] for _ in range(3)] == [True, True, False]


def test_identity_signature_detects_tampering():
    ident = IdentityAuthority.issue(copy.deepcopy(CUSTOMER_001))
    assert IdentityAuthority.verify(ident)[0]
    ident.role = "admin"
    assert not IdentityAuthority.verify(ident)[0]
    assert not IdentityAuthority.verify(copy.deepcopy(CUSTOMER_001))[0]        # unsigned


def test_circuit_breaker_opens_and_stays_open():
    cb = CircuitBreaker("x", threshold=2)
    cb.record_failure()
    assert cb.allow()
    cb.record_failure()
    assert not cb.allow() and cb.state == "OPEN"
    cb.record_success()
    assert cb.state == "OPEN"


def test_supervisor_kill_switch():
    sup = AgentSupervisor({"R": {"objective": "x", "tools": ["a"], "may_contact": [], "memory_write": []}}, anomaly_threshold=2)
    assert sup.check("R", "tool", "a")[0]
    assert not sup.check("R", "tool", "b")[0]
    ok, why = sup.check("R", "tool", "c")
    assert not ok and sup.is_disabled("R")
    assert not sup.check("R", "tool", "a")[0]                                   # even allowed tools are refused after the kill


def test_risk_model_is_deterministic():
    assert classify_risk(100, True) == "LOW"
    assert classify_risk(1500, False) == "HIGH"
    assert classify_risk(12000, True) == "HIGH"
    assert classify_risk(30000, True) == "CRITICAL"


# -- gateway ---------------------------------------------------------------

def test_gateway_blocks_unknown_tool():
    env, tr, ident, gw = _gw()
    r = gw.request("rm_rf_everything", {}, ident)
    assert r["status"] == "blocked" and r["blocked_at"] == "GUARDRAIL"


@pytest.mark.parametrize("forged", ["user_authorized", "approved", "override_risk", "as_user", "caller_role"])
def test_gateway_rejects_forged_authority_arguments(forged):
    env, tr, ident, gw = _gw()
    r = gw.request("get_account_balance", {"account_id": "ACC-1001", forged: True}, ident)
    assert r["status"] == "blocked"


def test_high_risk_transfer_is_held_and_never_executes_without_human():
    env, tr, ident, gw = _gw()
    r = gw.request("create_simulated_transaction", {"from_account": "ACC-1002", "to_account": "ACC-9999", "amount": 12000}, ident)
    assert r["status"] == "approval_required"
    assert env.ledger_diff()["balance_changes"] == {}
    assert env.approvals.list_pending()


def test_ai_cannot_approve_its_own_transfer():
    env, tr, ident, gw = _gw()
    for approver in ("AI_AGENT", "ORCHESTRATOR", "LLM", ident.user_id):
        r = gw.request("create_simulated_transaction", {"from_account": "ACC-1002", "to_account": "ACC-9999", "amount": 12000}, ident, approved_by=approver)
        assert r["status"] == "blocked", approver
    assert env.ledger_diff()["balance_changes"] == {}


def test_human_approval_path_executes_through_mcp():
    env, tr, ident, gw = _gw()
    r = gw.request("create_simulated_transaction", {"from_account": "ACC-1002", "to_account": "ACC-2001", "amount": 11000}, ident, approved_by="SUPPORT-001")
    assert r["status"] == "success"
    assert env.ledger_diff()["balance_changes"] == {"ACC-1002": -11000.0, "ACC-2001": 11000.0}


@pytest.mark.parametrize("amount", ["NaN", "inf", -5, 0, "abc", None, 60000])
def test_invalid_amounts_rejected(amount):
    env, tr, ident, gw = _gw()
    r = gw.request("create_simulated_transaction", {"from_account": "ACC-1001", "to_account": "ACC-1002", "amount": amount}, ident)
    assert r["status"] == "blocked"


def test_ownership_enforced_for_customers():
    env, tr, ident, gw = _gw()
    assert gw.request("get_account_balance", {"account_id": "ACC-2001"}, ident)["status"] == "blocked"
    assert gw.request("get_account_balance", {"account_id": "ACC-1001"}, ident)["status"] == "success"


def test_every_secure_decision_is_audited():
    from observability.audit import get_audit_logger
    env, tr, ident, gw = _gw()
    gw.request("get_account_balance", {"account_id": "ACC-2001"}, ident)
    assert get_audit_logger().get_by_request_id(tr.trace_id)
