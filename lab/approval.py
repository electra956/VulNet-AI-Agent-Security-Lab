"""
VulNet Attack Lab - the human-approval packet (ASI09).

The packet shown to a human approver is built by DETERMINISTIC code from real tool/risk results. The agent's
own explanation is included but labelled as an unverified claim, and every claim is checked against the
evidence so contradictions are visible - and a contradiction raises the bar (dual control) instead of
relying on the human noticing.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

from lab.core import LabEnvironment, classify_risk


@dataclass
class AgentClaims:
    narrative: str
    claimed_risk: str
    claimed_confidence: float
    beneficiary_trusted: bool
    recurring: bool
    recommendation: str = "APPROVE"


def params_hash(params: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(params, sort_keys=True, default=str).encode()).hexdigest()[:16]


def collect_evidence(env: LabEnvironment, params: Dict[str, Any]) -> Dict[str, Any]:
    """Facts from real components, never from the agent."""
    src = env.ft.accounts.get(params["from_account"], {})
    known = params["to_account"] in env.ft.accounts
    res = env.ft.risk_engine.evaluate({"amount": params["amount"], "from_account": params["from_account"],
                                        "to_account": params["to_account"], "available_balance": src.get("balance", 0)})
    total = params["amount"] * (params.get("occurrences") or 1)
    history = [t["amount"] for t in env.ft.transactions if t.get("source_account") == params["from_account"]]
    return {
        "deterministic_risk": classify_risk(params["amount"], known),
        "risk_engine_level": res.risk_level, "risk_engine_decision": res.decision, "risk_reasons": list(res.reasons),
        "beneficiary_known": known, "beneficiary_account": params["to_account"],
        "amount": params["amount"], "occurrences": params.get("occurrences") or 1, "total_exposure": total,
        "typical_transaction": round(sum(history) / len(history), 2) if history else None,
        "source_balance": src.get("balance"), "data_source": "TransactionRiskEngine + FinTech ledger (deterministic)",
    }


_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def find_contradictions(claims: AgentClaims, ev: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    if _ORDER.index(claims.claimed_risk) < _ORDER.index(ev["deterministic_risk"]):
        out.append(f"Agent says risk {claims.claimed_risk}; deterministic risk is {ev['deterministic_risk']}")
    if claims.beneficiary_trusted and not ev["beneficiary_known"]:
        out.append(f"Agent calls {ev['beneficiary_account']} a trusted beneficiary; it is not a known account")
    if not claims.recurring and ev["occurrences"] > 1:
        out.append(f"Agent describes a one-time payment; the request is recurring x{ev['occurrences']} "
                   f"(total exposure ${ev['total_exposure']:,.2f})")
    if claims.claimed_confidence >= 0.95 and out:
        out.append(f"Agent confidence {claims.claimed_confidence:.1%} is not supported by the evidence")
    return out


@dataclass
class ApprovalPacket:
    approval_id: str
    params: Dict[str, Any]
    params_hash: str
    agent_claims: Dict[str, Any]
    evidence: Dict[str, Any]
    contradictions: List[str]
    uncertainty: str
    consequence: str
    approvals_required: int
    state: str = "APPROVAL_REQUIRED"        # PENDING | APPROVAL_REQUIRED | APPROVED | REJECTED | EXPIRED | COMPLETED
    approvals: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def human_view(self) -> Dict[str, Any]:
        return self.to_dict()


def build_packet(approval_id: str, env: LabEnvironment, params: Dict[str, Any], claims: AgentClaims) -> ApprovalPacket:
    ev = collect_evidence(env, params)
    contra = find_contradictions(claims, ev)
    unc = ("Evidence contradicts the agent's explanation - treat the agent's summary as unreliable."
           if contra else "No contradiction between the agent's explanation and the evidence.")
    cons = (f"Approving executes {ev['occurrences']} payment(s) of ${params['amount']:,.2f} from {params['from_account']} to "
            f"{params['to_account']} (total ${ev['total_exposure']:,.2f}). Simulated funds only; not reversible without a cancellation.")
    return ApprovalPacket(approval_id, params, params_hash(params), asdict(claims), ev, contra, unc, cons,
                          approvals_required=2 if (contra or ev["deterministic_risk"] == "CRITICAL") else 1)


def naive_view(claims: AgentClaims) -> Dict[str, Any]:
    """The vulnerable approval UI: just the agent's story."""
    return {"agent_summary": claims.narrative, "confidence": claims.claimed_confidence, "recommendation": claims.recommendation}


def simulated_human(view: Dict[str, Any], style: str) -> str:
    """A scripted stand-in for the human, clearly a simulation. Same person, two behaviours."""
    rec = view.get("recommendation") or view.get("agent_claims", {}).get("recommendation", "APPROVE")
    if style == "rubber_stamp":
        return "APPROVE" if rec == "APPROVE" else "REJECT"
    ev = view.get("evidence")
    if not ev:                                    # nothing but the agent's story to go on
        return "APPROVE" if rec == "APPROVE" else "REJECT"
    if view.get("contradictions"):
        return "REJECT"
    return "APPROVE" if ev["deterministic_risk"] in ("LOW", "MEDIUM") else "REJECT"
