"""ASI07: inter-agent bus validation."""

import copy

from lab.bus import AgentBus, BUS_POLICY, build_agents, build_message
from lab.core import AttackTrace, CUSTOMER_001, LabEnvironment, ToolGateway
from lab.controls import IdentityAuthority

P = {"from_account": "ACC-1001", "to_account": "ACC-1002", "amount": 25, "description": "t"}


def _bus(mode):
    env = LabEnvironment(mode)
    tr = AttackTrace("T", mode)
    ident = IdentityAuthority.issue(copy.deepcopy(CUSTOMER_001)) if mode == "secure" else copy.deepcopy(CUSTOMER_001)
    gw = ToolGateway(env, tr, mode)
    return env, AgentBus(mode, tr, build_agents(env, gw, tr, ident)), tr


def test_valid_signed_message_is_delivered():
    env, bus, tr = _bus("secure")
    r = bus.send(build_message("Orchestrator", "TransactionAgent", "txn.execute_transfer", P, "R1", on_behalf_of="CUST-001"))
    assert r["status"] == "success"
    assert env.ledger_diff()["balance_changes"] == {"ACC-1001": -25.0, "ACC-1002": 25.0}


def test_spoofed_sender_rejected():
    env, bus, _ = _bus("secure")
    m = build_message("Orchestrator", "TransactionAgent", "txn.execute_transfer", P, "R1", sign_as="ResearchAgent")
    r = bus.send(m)
    assert r["status"] == "blocked" and r["control"] == "SIGNATURE"
    assert env.ledger_diff()["balance_changes"] == {}


def test_tampered_payload_rejected():
    _, bus, _ = _bus("secure")
    m = build_message("Orchestrator", "TransactionAgent", "txn.execute_transfer", P, "R1")
    m.payload["amount"] = 9999
    assert bus.send(m)["control"] in ("SIGNATURE", "INTEGRITY")


def test_replay_rejected():
    env, bus, _ = _bus("secure")
    m = build_message("Orchestrator", "TransactionAgent", "txn.execute_transfer", P, "R1")
    assert bus.send(m)["status"] == "success"
    assert bus.send(copy.deepcopy(m))["control"] == "REPLAY"


def test_authorization_matrix_enforced():
    _, bus, _ = _bus("secure")
    m = build_message("SupportAgent", "TransactionAgent", "txn.execute_transfer", P, "R1")
    assert bus.send(m)["control"] == "AUTHORIZATION"
    assert ("SupportAgent", "TransactionAgent") not in BUS_POLICY


def test_unknown_receiver_and_intent_and_schema():
    _, bus, _ = _bus("secure")
    assert bus.send(build_message("Orchestrator", "GhostAgent", "txn.status", {"transaction_id": "T"}, "R"))["control"] == "RECEIVER_IDENTITY"
    assert bus.send(build_message("Orchestrator", "TransactionAgent", "do.anything", {"x": 1}, "R"))["control"] == "MESSAGE_SCHEMA"
    assert bus.send(build_message("Orchestrator", "TransactionAgent", "txn.execute_transfer", {"amount": 1}, "R"))["control"] == "MESSAGE_SCHEMA"


def test_vulnerable_bus_delivers_forged_messages():
    env, bus, _ = _bus("vulnerable")
    m = build_message("FraudAgent", "TransactionAgent", "txn.execute_transfer", P, "R1")
    m.authentication["signature"] = "00" * 32
    assert bus.send(m)["status"] == "success"


def test_agents_have_distinct_responsibilities():
    env, bus, _ = _bus("secure")
    manifests = {n: a.manifest() for n, a in bus.agents.items()}
    tool_sets = {n: tuple(m["tools"]) for n, m in manifests.items() if n != "Orchestrator"}
    assert len(set(tool_sets.values())) == len(tool_sets)
    assert "create_simulated_transaction" in manifests["TransactionAgent"]["tools"]
    assert "create_simulated_transaction" not in manifests["ResearchAgent"]["tools"]
