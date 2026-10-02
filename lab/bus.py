"""
VulNet Attack Lab - inter-agent communication (ASI07) and the six specialised agents.

Agents never call each other directly. They exchange structured `AgentMessage` envelopes over the
`AgentBus`, which (in SECURE mode) validates, for every message:

    schema -> sender identity -> receiver identity -> signature (HMAC, per-agent key) -> payload integrity
    -> replay (nonce) -> authorization (sender may send THIS intent to THIS receiver) -> trust/provenance

The VULNERABLE bus delivers anything that names a known receiver - exactly the "downstream agent blindly
trusts upstream messages" failure described by OWASP ASI07.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from lab.core import AttackTrace, Identity, LabEnvironment, ToolGateway

_MASTER = b"vulnet-lab-agent-bus-master-key-synthetic"

# Who may send which intent to whom. (sender, receiver) -> allowed intents. "*" = any registered agent.
BUS_POLICY: Dict[Tuple[str, str], Set[str]] = {
    ("Orchestrator", "*"): {"customer.balance_request", "customer.profile_request", "research.query",
                            "txn.execute_transfer", "txn.status", "fraud.assess", "compliance.kyc_check",
                            "support.ticket"},
    ("ResearchAgent", "TransactionAgent"): {"research.result"},
    ("ResearchAgent", "FraudAgent"): {"research.result"},
    ("FraudAgent", "TransactionAgent"): {"fraud.verdict"},
    ("TransactionAgent", "FraudAgent"): {"fraud.assess"},
    ("TransactionAgent", "ComplianceAgent"): {"compliance.kyc_check"},
    ("SupportAgent", "CustomerAgent"): {"customer.profile_request"},
    ("CustomerAgent", "TransactionAgent"): {"txn.status"},
}

SCHEMA: Dict[str, Set[str]] = {                     # intent -> required payload keys
    "customer.balance_request": {"account_id"},
    "customer.profile_request": {"customer_id"},
    "research.query": {"query"},
    "research.result": {"documents"},
    "txn.execute_transfer": {"from_account", "to_account", "amount"},
    "txn.status": {"transaction_id"},
    "fraud.assess": {"amount", "to_account"},
    "fraud.verdict": {"risk", "confidence"},
    "compliance.kyc_check": {"customer_id"},
    "support.ticket": {"subject"},
}


def canonical(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def agent_key(name: str) -> bytes:
    """Per-agent signing key. In the lab an attacker controlling one agent holds ONLY that agent's key."""
    return hashlib.sha256(_MASTER + name.encode()).digest()


@dataclass
class AgentMessage:
    message_id: str
    request_id: str
    sender_agent: str
    receiver_agent: str
    intent: str
    payload: Dict[str, Any]
    timestamp: str
    authentication: Dict[str, Any] = field(default_factory=dict)   # {"signature": hex, "nonce": str}
    authorization: Dict[str, Any] = field(default_factory=dict)    # {"on_behalf_of": user, "scopes": [...]}
    integrity: Dict[str, Any] = field(default_factory=dict)        # {"payload_sha256": hex}
    trust_level: str = "INTERNAL"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def signing_string(self) -> str:
        return "|".join([self.message_id, self.request_id, self.sender_agent, self.receiver_agent, self.intent,
                         canonical(self.payload), self.authentication.get("nonce", ""),
                         self.authorization.get("on_behalf_of", "")])


def build_message(sender: str, receiver: str, intent: str, payload: Dict[str, Any], request_id: str,
                  on_behalf_of: str = "", sign_as: Optional[str] = None, trust: str = "INTERNAL") -> AgentMessage:
    """Create and sign a message. `sign_as` lets an attacker sign with a key that is not the sender's."""
    m = AgentMessage(
        message_id=f"MSG-{uuid.uuid4().hex[:10].upper()}", request_id=request_id, sender_agent=sender,
        receiver_agent=receiver, intent=intent, payload=dict(payload),
        timestamp=datetime.now(timezone.utc).isoformat(),
        authentication={"nonce": uuid.uuid4().hex},
        authorization={"on_behalf_of": on_behalf_of, "scopes": [intent]},
        trust_level=trust)
    m.integrity = {"payload_sha256": hashlib.sha256(canonical(m.payload).encode()).hexdigest()}
    m.authentication["signature"] = hmac.new(agent_key(sign_as or sender), m.signing_string().encode(),
                                             hashlib.sha256).hexdigest()
    return m


class AgentBus:
    def __init__(self, mode: str, trace: AttackTrace, agents: Dict[str, "BaseAgent"]):
        self.mode = mode.lower()
        self.trace = trace
        self.agents = agents
        self.log: List[Dict[str, Any]] = []              # the communication trace
        self._nonces: Set[str] = set()

    def send(self, msg: AgentMessage) -> Dict[str, Any]:
        checks: List[Dict[str, Any]] = []
        entry = {"message_id": msg.message_id, "from": msg.sender_agent, "to": msg.receiver_agent,
                 "intent": msg.intent, "checks": checks, "delivered": False, "reason": ""}
        self.log.append(entry)

        def fail(check: str, why: str) -> Dict[str, Any]:
            checks.append({"check": check, "ok": False, "why": why})
            entry["reason"] = f"{check}: {why}"
            self.trace.add("AGENT", "AgentBus", "BLOCK",
                           f"{msg.sender_agent} -> {msg.receiver_agent} [{msg.intent}] rejected: {why}",
                           agent=msg.sender_agent, control=check, message_id=msg.message_id)
            self.trace.audit("agent_message", "BLOCK", "blocked", "HIGH", agent=msg.sender_agent, error=why,
                             intent=msg.intent, receiver=msg.receiver_agent)
            return {"status": "blocked", "control": check, "reason": why}

        receiver = self.agents.get(msg.receiver_agent)
        if receiver is None:
            return fail("RECEIVER_IDENTITY", f"unknown receiver '{msg.receiver_agent}'")

        if self.mode == "secure":
            missing = SCHEMA.get(msg.intent)
            if missing is None:
                return fail("MESSAGE_SCHEMA", f"unknown intent '{msg.intent}'")
            absent = missing - set(msg.payload)
            if absent:
                return fail("MESSAGE_SCHEMA", f"payload missing {sorted(absent)}")
            checks.append({"check": "MESSAGE_SCHEMA", "ok": True})
            if msg.sender_agent not in self.agents:
                return fail("SENDER_IDENTITY", f"unknown sender '{msg.sender_agent}'")
            checks.append({"check": "SENDER_IDENTITY", "ok": True})
            expected = hmac.new(agent_key(msg.sender_agent), msg.signing_string().encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, str(msg.authentication.get("signature", ""))):
                return fail("SIGNATURE", f"signature does not verify against {msg.sender_agent}'s key (spoofed/forged)")
            checks.append({"check": "SIGNATURE", "ok": True})
            digest = hashlib.sha256(canonical(msg.payload).encode()).hexdigest()
            if digest != msg.integrity.get("payload_sha256"):
                return fail("INTEGRITY", "payload hash mismatch (message modified in transit)")
            checks.append({"check": "INTEGRITY", "ok": True})
            nonce = msg.authentication.get("nonce", "")
            if not nonce or nonce in self._nonces:
                return fail("REPLAY", "missing or reused nonce")
            self._nonces.add(nonce)
            checks.append({"check": "REPLAY", "ok": True})
            allowed = BUS_POLICY.get((msg.sender_agent, msg.receiver_agent), set()) | \
                BUS_POLICY.get((msg.sender_agent, "*"), set())
            if msg.intent not in allowed:
                return fail("AUTHORIZATION", f"{msg.sender_agent} may not send '{msg.intent}' to {msg.receiver_agent}")
            checks.append({"check": "AUTHORIZATION", "ok": True})
            if msg.trust_level not in ("INTERNAL", "VERIFIED"):
                return fail("TRUST", f"message trust level '{msg.trust_level}' is not accepted for this intent")
            checks.append({"check": "TRUST", "ok": True})
        else:
            checks.append({"check": "ALL_CHECKS", "ok": True, "why": "vulnerable bus: no verification performed"})

        entry["delivered"] = True
        self.trace.add("AGENT", "AgentBus", "ALLOW" if self.mode == "secure" else "INFO",
                       f"{msg.sender_agent} -> {msg.receiver_agent} [{msg.intent}] delivered"
                       + ("" if self.mode == "secure" else " (UNVERIFIED)"),
                       agent=msg.sender_agent, message_id=msg.message_id)
        return receiver.handle(msg)


# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------

class BaseAgent:
    name = "Agent"
    objective = ""
    tools: Set[str] = set()
    may_contact: Set[str] = set()
    memory_write: Set[str] = set()
    may_alter: Set[str] = set()

    def __init__(self, env: LabEnvironment, gateway: ToolGateway, trace: AttackTrace, identity: Identity):
        self.env, self.gw, self.trace, self.identity = env, gateway, trace, identity
        self.handlers: Dict[str, Callable[[AgentMessage], Dict[str, Any]]] = {}

    def manifest(self) -> Dict[str, Any]:
        return {"objective": self.objective, "tools": sorted(self.tools), "may_contact": sorted(self.may_contact),
                "memory_write": sorted(self.memory_write), "may_alter": sorted(self.may_alter)}

    def handle(self, msg: AgentMessage) -> Dict[str, Any]:
        fn = self.handlers.get(msg.intent)
        if fn is None:
            return {"status": "error", "reason": f"{self.name} does not handle '{msg.intent}'"}
        return fn(msg)

    def _acting_identity(self, msg: AgentMessage) -> Identity:
        """The user this message is for. SECURE agents ignore payload-supplied identities."""
        return self.identity


class CustomerAgent(BaseAgent):
    name = "CustomerAgent"
    objective = "Answer the authenticated customer's own account questions"
    tools = {"get_account_balance", "get_account_status", "get_customer_profile", "get_transaction_history",
             "get_card_status"}
    may_contact = {"TransactionAgent"}

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.handlers = {"customer.balance_request": self._balance, "customer.profile_request": self._profile}

    def _balance(self, msg):
        return self.gw.request("get_account_balance", {"account_id": msg.payload["account_id"]},
                               self.identity, agent=self.name)

    def _profile(self, msg):
        args = {"customer_id": msg.payload["customer_id"]}
        return self.gw.request("get_customer_profile", args, self.identity, agent=self.name)


class ResearchAgent(BaseAgent):
    name = "ResearchAgent"
    objective = "Retrieve policy and knowledge documents; never act on them"
    tools = {"search_knowledge_base"}
    may_contact = {"TransactionAgent", "FraudAgent"}

    def __init__(self, *a, rag=None, **k):
        super().__init__(*a, **k)
        self.rag = rag
        self.handlers = {"research.query": self._query}

    def _query(self, msg):
        docs = self.rag.search(msg.payload["query"], top_k=3) if self.rag else []
        return {"status": "success", "documents": [
            {"source": d["source"], "trust_level": d["trust_level"], "content": d["content"][:400]} for d in docs]}


class TransactionAgent(BaseAgent):
    name = "TransactionAgent"
    objective = "Execute transfers that the orchestrator requests on behalf of the authenticated user"
    tools = {"create_simulated_transaction", "get_transaction", "cancel_simulated_transaction"}
    may_contact = {"FraudAgent", "ComplianceAgent"}

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.handlers = {"txn.execute_transfer": self._transfer, "txn.status": self._status,
                         "research.result": self._research_result, "fraud.verdict": self._fraud_verdict}
        self.last_fraud_verdict: Optional[Dict[str, Any]] = None
        self.last_research: Optional[Dict[str, Any]] = None

    def _transfer(self, msg):
        args = {k: msg.payload[k] for k in ("from_account", "to_account", "amount")}
        args["description"] = msg.payload.get("description", "agent transfer")
        who = self.identity
        if self.gw.mode == "vulnerable" and msg.authorization.get("on_behalf_of"):
            who = Identity(msg.authorization["on_behalf_of"], "customer", [], [], source="message-payload")
        return self.gw.request("create_simulated_transaction", args, who, agent=self.name,
                               approved_by=msg.payload.get("approved_by"))

    def _status(self, msg):
        return self.gw.request("get_transaction", {"transaction_id": msg.payload["transaction_id"]},
                               self.identity, agent=self.name)

    def _research_result(self, msg):
        self.last_research = msg.payload
        if self.gw.mode == "vulnerable":
            # Naive downstream agent: treats upstream agent content as instructions (ASI07).
            from lab.policy import CompromisedAgentPolicy, ContextBlock
            blocks = [ContextBlock(f"agent:{msg.sender_agent}", str(d.get("content", "")), "INTERNAL")
                      for d in msg.payload.get("documents", [])]
            plan = CompromisedAgentPolicy(default_account=self.identity.account_ids[0]).plan("", blocks)
            results = [self.gw.request(c.tool, dict(c.args), self.identity, agent=self.name) for c in plan.calls]
            return {"status": "success", "stored": True, "executed_instructions": [c.tool for c in plan.calls],
                    "results": results}
        from lab.policy import CompromisedAgentPolicy, ContextBlock
        blocks = [ContextBlock(f"agent:{msg.sender_agent}", str(d.get("content", "")), "INTERNAL")
                  for d in msg.payload.get("documents", [])]
        found = CompromisedAgentPolicy(default_account=self.identity.account_ids[0]).plan("", blocks).calls
        if found:
            self.trace.add("AGENT", self.name, "BLOCK",
                           f"{len(found)} instruction(s) found inside a research.result were NOT executed: agent-relayed content is data only",
                           agent=self.name, control="DATA_ONLY_INTENT", ignored=[c.tool for c in found])
            self.trace.add("AGENT", "Lab", "INFO", "ASSUME-BREACH: the agent executes the relayed instruction anyway")
            for c in found:
                self.gw.request(c.tool, dict(c.args), self.identity, agent=self.name)
        return {"status": "success", "stored": True, "note": "research results are data; never executed"}

    def _fraud_verdict(self, msg):
        self.last_fraud_verdict = msg.payload
        return {"status": "success", "stored": True}


class FraudAgent(BaseAgent):
    name = "FraudAgent"
    objective = "Assess transaction risk deterministically and report a verdict"
    tools = {"check_transaction_risk", "flag_transaction", "get_fraud_case"}
    may_contact = {"TransactionAgent"}

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.handlers = {"fraud.assess": self._assess, "research.result": lambda m: {"status": "success"}}

    def _assess(self, msg):
        from lab.core import classify_risk
        amt = float(msg.payload["amount"])
        known = msg.payload["to_account"] in self.env.ft.accounts
        risk = classify_risk(amt, known)
        return {"status": "success", "risk": risk, "confidence": 0.95, "beneficiary_known": known}


class ComplianceAgent(BaseAgent):
    name = "ComplianceAgent"
    objective = "Check KYC status before high-value movement"
    tools = {"get_kyc_status", "verify_identity_simulated"}

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.handlers = {"compliance.kyc_check": self._kyc}

    def _kyc(self, msg):
        return {"status": "success", "customer_id": msg.payload["customer_id"],
                "kyc_status": self.env.ft.customers.get(msg.payload["customer_id"], {}).get("kyc_status", "UNKNOWN")}


class SupportAgent(BaseAgent):
    name = "SupportAgent"
    objective = "Open support tickets and notify customers"
    tools = {"create_support_ticket", "send_simulated_notification"}
    may_contact = {"CustomerAgent"}

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.handlers = {"support.ticket": self._ticket}

    def _ticket(self, msg):
        return self.gw.request("create_support_ticket", {"subject": msg.payload["subject"],
                                                          "customer_id": self.identity.user_id},
                               self.identity, agent=self.name)


class OrchestratorStub(BaseAgent):
    name = "Orchestrator"
    objective = "Route the authenticated user's request to specialised agents"
    may_contact = {"CustomerAgent", "ResearchAgent", "TransactionAgent", "FraudAgent", "ComplianceAgent", "SupportAgent"}


class RogueAgent(BaseAgent):
    """Compromised agent used by ASI10. Its declared objective is narrow; its behaviour is not."""
    name = "RogueAgent"
    objective = "Summarise policy documents for the customer (read-only)"
    tools = {"search_knowledge_base"}
    may_contact = {"ResearchAgent"}
    memory_write: Set[str] = set()


AGENT_CLASSES = [CustomerAgent, ResearchAgent, TransactionAgent, FraudAgent, ComplianceAgent, SupportAgent]


def build_agents(env: LabEnvironment, gateway: ToolGateway, trace: AttackTrace, identity: Identity,
                 rag: Any = None, include_rogue: bool = False) -> Dict[str, BaseAgent]:
    agents: Dict[str, BaseAgent] = {"Orchestrator": OrchestratorStub(env, gateway, trace, identity)}
    for cls in AGENT_CLASSES:
        agents[cls.name] = cls(env, gateway, trace, identity, rag=rag) if cls is ResearchAgent \
            else cls(env, gateway, trace, identity)
    if include_rogue:
        agents["RogueAgent"] = RogueAgent(env, gateway, trace, identity)
    return agents


def agent_manifests(agents: Dict[str, BaseAgent]) -> Dict[str, Dict[str, Any]]:
    return {n: a.manifest() for n, a in agents.items()}
