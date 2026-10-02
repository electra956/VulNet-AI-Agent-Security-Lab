"""
VulNet AI Agent Security Lab - Attack Lab core.

Shared building blocks for the executable OWASP Agentic Top 10 (2026) scenarios:

  * AttackTrace / TraceStep  - the observable attack path (ATTACK INPUT -> ... -> AUDIT)
  * ScenarioResult           - structured, serialisable evidence of one run
  * LabEnvironment           - a fresh, fully synthetic FinTech world per run
  * ToolGateway              - the tool boundary, in a deliberately weak VULNERABLE form and a
                               layered SECURE form (goal scope -> guardrail -> RBAC -> ownership ->
                               risk -> approval -> MCP). Every stage is recorded in the trace.

Everything here is local and synthetic. No real money, credentials, hosts or networks are touched.
"""

from __future__ import annotations

import copy
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from auth.authorization import has_permission
from auth.permissions import Permission
from auth.roles import Role, normalize_role
from mcp_server.fintech_tools import FinTechToolSuite
from mcp_server.server import MCPServer
from mcp_server.tools import create_default_registry
from observability.audit import get_audit_logger
from security.approval_engine import ApprovalEngine
from security.security_controller import SecurityController

# The observable attack path, in canonical order.
STAGES = [
    "ATTACK_INPUT", "AGENT", "RAG_MEMORY", "TOOL_REQUEST", "GUARDRAIL", "RBAC",
    "RISK", "APPROVAL", "MCP", "TOOL", "RESULT", "AUDIT",
]

# Step verdicts. ATTACK_EFFECT marks a step where the attack actually took effect (vulnerable path).
VERDICTS = {"INFO", "ALLOW", "BLOCK", "REVIEW", "APPROVAL_REQUIRED", "ATTACK_EFFECT", "ERROR"}

LAB_LABEL = "SYNTHETIC LAB DATA - no real customers, credentials, banks or funds"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class TraceStep:
    stage: str
    component: str
    verdict: str
    detail: str
    data: Dict[str, Any] = field(default_factory=dict)
    agent: Optional[str] = None
    timestamp: str = field(default_factory=_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AttackTrace:
    """Ordered record of everything that happened while a scenario ran. Also mirrors to the audit log."""

    def __init__(self, scenario_id: str, mode: str, user_id: str = "CUST-001"):
        self.trace_id = f"TRC-{uuid.uuid4().hex[:12].upper()}"
        self.scenario_id = scenario_id
        self.mode = mode
        self.user_id = user_id
        self.session_id = f"LAB-{self.trace_id[4:12]}"
        self.steps: List[TraceStep] = []
        self._t0 = time.perf_counter()
        self._audit = get_audit_logger()

    def add(self, stage: str, component: str, verdict: str, detail: str, /,
            agent: Optional[str] = None, **data: Any) -> TraceStep:
        assert stage in STAGES, f"unknown stage {stage}"
        assert verdict in VERDICTS, f"unknown verdict {verdict}"
        step = TraceStep(stage=stage, component=component, verdict=verdict, detail=detail,
                         data=_jsonable(data), agent=agent)
        self.steps.append(step)
        return step

    def audit(self, action: str, decision: str, status: str, risk: str = "LOW",
              agent: Optional[str] = None, tool: Optional[str] = None,
              error: Optional[str] = None, **meta: Any) -> str:
        """Write a real audit record (logs/audit.jsonl) and add the AUDIT step to the trace."""
        rec = self._audit.log_audit(
            request_id=self.trace_id, session_id=self.session_id, user_id=self.user_id,
            action=action, decision=decision, status=status, agent=agent, tool=tool, risk=risk,
            error=error, latency_ms=int((time.perf_counter() - self._t0) * 1000),
            metadata={"scenario": self.scenario_id, "mode": self.mode, **_jsonable(meta)},
        )
        self.add("AUDIT", "AuditLogger", "INFO", f"{rec.audit_id}: {action} -> {decision}",
                 agent=agent, audit_id=rec.audit_id)
        return rec.audit_id

    def first(self, verdict: str) -> Optional[TraceStep]:
        return next((s for s in self.steps if s.verdict == verdict), None)

    def blocked_at(self) -> Optional[TraceStep]:
        """First step that actually stopped something (BLOCK / APPROVAL_REQUIRED), else the first REVIEW."""
        return (next((s for s in self.steps if s.verdict in ("BLOCK", "APPROVAL_REQUIRED")), None)
                or next((s for s in self.steps if s.verdict == "REVIEW"), None))

    def took_effect(self) -> bool:
        return any(s.verdict == "ATTACK_EFFECT" for s in self.steps)

    def to_list(self) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in self.steps]


def _jsonable(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, float) and (obj != obj or obj in (float("inf"), float("-inf"))):
        return str(obj)                                  # NaN / Infinity are not valid JSON
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    if hasattr(obj, "to_dict"):
        try:
            return _jsonable(obj.to_dict())
        except Exception:
            pass
    return str(obj)


@dataclass
class ScenarioResult:
    """Evidence of one scenario execution in one mode."""
    scenario_id: str
    variant: str
    mode: str
    title: str
    attack_input: Any
    steps: List[Dict[str, Any]]
    outcome: str                     # ATTACK_SUCCEEDED | ATTACK_BLOCKED | CONTAINED
    impact: Dict[str, Any]           # measurable change inside the lab (ledger, loot, state)
    blocked_by: Optional[str]        # control that stopped it (secure), else None
    controls_observed: List[str]
    evidence: Dict[str, Any]
    trace_id: str
    decision_engine: str = "deterministic-policy"
    timestamp: str = field(default_factory=_now)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return _jsonable(asdict(self))

    @property
    def attack_succeeded(self) -> bool:
        return self.outcome == "ATTACK_SUCCEEDED"


# ---------------------------------------------------------------------------
# Synthetic world
# ---------------------------------------------------------------------------

class LabEnvironment:
    """A fresh synthetic FinTech world: ledger + MCP server + approvals + security telemetry."""

    def __init__(self, mode: str):
        self.mode = mode.lower()
        self.security = SecurityController(mode=self.mode)
        self.ft = FinTechToolSuite()                       # accounts, cards, transactions (synthetic)
        self.registry = create_default_registry(self.ft)
        self.mcp = MCPServer(mode=self.mode, security_controller=self.security, registry=self.registry)
        self.approvals = ApprovalEngine(self.security)
        self._baseline = self.snapshot()

    # -- ledger helpers ------------------------------------------------
    def snapshot(self) -> Dict[str, Any]:
        return {
            "balances": {a: v["balance"] for a, v in self.ft.accounts.items()},
            "transactions": len(self.ft.transactions),
            "cards": {c: v["status"] for c, v in self.ft.cards.items()},
        }

    def ledger_diff(self) -> Dict[str, Any]:
        now = self.snapshot()
        moved = {a: round(now["balances"].get(a, 0) - b, 2) for a, b in self._baseline["balances"].items()
                 if round(now["balances"].get(a, 0) - b, 2) != 0}
        created = {a: now["balances"][a] for a in now["balances"] if a not in self._baseline["balances"]}
        return {
            "balance_changes": moved,
            "new_accounts": created,
            "new_transactions": now["transactions"] - self._baseline["transactions"],
            "card_changes": {c: s for c, s in now["cards"].items() if self._baseline["cards"].get(c) != s},
            "real_funds_moved": False,
        }

    def raw_transfer(self, src: str, dst: str, amount: float, user: str, note: str = "") -> Dict[str, Any]:
        """UNCHECKED ledger write - what a careless tool backend does. Only the vulnerable gateway uses it."""
        s = self.ft.accounts.get(src)
        if s is None:
            return {"status": "error", "reason": f"unknown source {src}"}
        amount = float(amount)
        s["balance"] = round(s["balance"] - amount, 2)
        if dst in self.ft.accounts:
            self.ft.accounts[dst]["balance"] = round(self.ft.accounts[dst]["balance"] + amount, 2)
        txn = {"transaction_id": f"TXN-LAB-{len(self.ft.transactions) + 1:05d}", "source_account": src,
               "destination_account": dst, "amount": amount, "currency": "USD", "status": "COMPLETED",
               "timestamp": _now(), "user_id": user, "description": note or "lab transfer",
               "approval_status": "NONE"}
        self.ft.transactions.insert(0, txn)
        return {"status": "success", "result": {**txn, "real_funds_moved": False}}


# ---------------------------------------------------------------------------
# Tool boundary
# ---------------------------------------------------------------------------

# Tool -> (permission, needs account ownership on which arg, financial?)
TOOL_POLICY: Dict[str, Dict[str, Any]] = {
    "get_account_balance": {"perm": Permission.ACCOUNT_READ, "owner_arg": "account_id"},
    "get_account_status": {"perm": Permission.ACCOUNT_READ, "owner_arg": "account_id"},
    "get_customer_profile": {"perm": Permission.ACCOUNT_READ, "customer_arg": "customer_id"},
    "get_transaction_history": {"perm": Permission.TRANSACTION_READ, "owner_arg": "account_id"},
    "get_transaction": {"perm": Permission.TRANSACTION_READ},
    "create_simulated_transaction": {"perm": Permission.TRANSACTION_CREATE, "owner_arg": "from_account", "financial": True},
    "cancel_simulated_transaction": {"perm": Permission.TRANSACTION_CANCEL},
    "create_simulated_payment": {"perm": Permission.TRANSACTION_CREATE, "owner_arg": "from_account", "financial": True},
    "get_payment_status": {"perm": Permission.TRANSACTION_READ},
    "cancel_simulated_payment": {"perm": Permission.TRANSACTION_CANCEL},
    "get_card_status": {"perm": Permission.CARD_READ, "owner_card_arg": "card_id"},
    "freeze_card": {"perm": Permission.CARD_FREEZE, "owner_card_arg": "card_id"},
    "unfreeze_card": {"perm": Permission.CARD_FREEZE, "owner_card_arg": "card_id"},
    "check_transaction_risk": {"perm": Permission.FRAUD_REVIEW},
    "flag_transaction": {"perm": Permission.FRAUD_REVIEW},
    "get_fraud_case": {"perm": Permission.FRAUD_REVIEW},
    "get_kyc_status": {"perm": Permission.KYC_READ, "customer_arg": "customer_id"},
    "verify_identity_simulated": {"perm": Permission.KYC_READ},
    "create_support_ticket": {"perm": Permission.SUPPORT_CREATE},
    "send_simulated_notification": {"perm": Permission.SUPPORT_CREATE},
    "search_knowledge_base": {"perm": Permission.ACCOUNT_READ},
    "get_security_status": {"perm": Permission.ACCOUNT_READ},
    # admin-only / role-restricted tools
    "modify_system_policy": {"perm": None, "roles": {"ADMIN"}},
    "execute_data_export": {"perm": None, "roles": {"ADMIN", "COMPLIANCE_ANALYST"}},
    # lab-implemented tools (implementation supplied by the scenario through `impls`)
    "run_analysis": {"perm": Permission.ACCOUNT_READ, "impl": True},
}

_INJECTION_IN_ARGS = [
    r"(?i)\bos\.system\b", r"(?i)\bsubprocess\b", r"(?i)__import__", r"(?i)\beval\s*\(", r"(?i)\bexec\s*\(",
    r"(?i)\bdrop\s+table\b", r"(?i)\bunion\s+select\b", r"(?i)\brm\s+-rf\b", r"(?i)<script", r"(?i);\s*--",
    r"(?i)ignore (all )?previous instructions",
]

# Amount at/above which a transfer needs a human (mirrors the simulated transaction policy).
APPROVAL_THRESHOLD = 10_000.0
HARD_LIMIT = 50_000.0


@dataclass
class Identity:
    """Authenticated identity. In the SECURE path this comes only from the auth service, never from the LLM."""
    user_id: str
    role: str
    account_ids: List[str] = field(default_factory=list)
    card_ids: List[str] = field(default_factory=list)
    source: str = "auth-service"          # provenance of this identity
    signature: str = ""                   # set by lab.controls.IdentityAuthority

    def role_enum(self) -> Role:
        return normalize_role(self.role)


CUSTOMER_001 = Identity("CUST-001", "customer", ["ACC-1001", "ACC-1002"], ["CARD-1001"])
CUSTOMER_002 = Identity("CUST-002", "customer", ["ACC-2001", "ACC-2002"], ["CARD-2001"])


class ToolGateway:
    """
    The tool boundary between an (untrusted) agent/LLM and the simulated FinTech backend.

    VULNERABLE mode is deliberately weak: it only checks that the tool exists, trusts any identity the
    caller asserts, and writes straight to the ledger. SECURE mode runs the full deterministic chain and
    records each stage in the trace, so the exact blocking control is visible.
    """

    def __init__(self, env: LabEnvironment, trace: AttackTrace, mode: str,
                 goal_guard: Optional[Any] = None, rate_limiter: Optional[Any] = None,
                 extra_tools: Optional[Dict[str, Callable[..., Dict[str, Any]]]] = None,
                 impls: Optional[Dict[str, Callable[..., Dict[str, Any]]]] = None):
        self.env = env
        self.impls = impls or {}
        self.trace = trace
        self.mode = mode.lower()
        self.goal_guard = goal_guard
        self.rate_limiter = rate_limiter
        self.extra_tools = extra_tools or {}
        self.calls: List[Dict[str, Any]] = []

    # -- public --------------------------------------------------------
    def request(self, tool: str, args: Dict[str, Any], identity: Identity, agent: str = "Agent",
                approved_by: Optional[str] = None) -> Dict[str, Any]:
        args = dict(args or {})
        self.trace.add("TOOL_REQUEST", "LLM/Agent", "INFO", f"{agent} requests {tool}", agent=agent,
                       tool=tool, arguments=args, as_user=identity.user_id, as_role=identity.role)
        self.calls.append({"tool": tool, "args": args, "agent": agent})
        if self.mode == "vulnerable":
            return self._vulnerable(tool, args, identity, agent)
        return self._secure(tool, args, identity, agent, approved_by)

    # -- vulnerable ------------------------------------------------------
    def _vulnerable(self, tool: str, args: Dict[str, Any], identity: Identity, agent: str) -> Dict[str, Any]:
        if tool in self.extra_tools:
            self.trace.add("GUARDRAIL", "ToolGuardrail", "ALLOW", "No guardrail: registered extra tool accepted", agent=agent)
            res = self.extra_tools[tool](**args)
            self.trace.add("TOOL", tool, "ATTACK_EFFECT", "Untrusted tool executed", agent=agent, result=res)
            return res
        if tool not in TOOL_POLICY and tool not in self.env.registry.list_tools():
            self.trace.add("GUARDRAIL", "ToolGuardrail", "BLOCK", f"Unknown tool '{tool}'", agent=agent)
            return {"status": "blocked", "reason": "unknown tool"}
        # Trust asserted identity fields blindly (ASI03) and skip every other control.
        asserted = args.pop("as_user", None) or args.pop("customer_id", None) or identity.user_id
        self.trace.add("GUARDRAIL", "ToolGuardrail", "ALLOW", "Vulnerable gateway: no argument, scope or goal checks", agent=agent)
        self.trace.add("RBAC", "RBAC", "ALLOW", f"Vulnerable gateway: role/ownership not enforced (acting as {asserted})", agent=agent)
        self.trace.add("RISK", "RiskEngine", "ALLOW", "Vulnerable gateway: risk engine bypassed", agent=agent)
        self.trace.add("APPROVAL", "ApprovalEngine", "ALLOW", "Vulnerable gateway: no human approval requested", agent=agent)
        self.trace.add("MCP", "MCPServer", "ALLOW", "Vulnerable gateway: MCP policy bypassed", agent=agent)
        res = self._execute_raw(tool, args, asserted, agent, identity)
        return res

    def _execute_raw(self, tool: str, args: Dict[str, Any], user: str, agent: str,
                     identity: Optional[Identity] = None) -> Dict[str, Any]:
        args = {k: v for k, v in args.items() if k not in ("user_authorized", "approved", "approval_override")}
        if tool in self.impls:
            res = self.impls[tool](**args)
            self.trace.add("TOOL", tool, "ATTACK_EFFECT" if res.get("attack_effect") else "INFO",
                           f"{tool} executed (lab implementation)", agent=agent, result=res)
            return res
        if tool in ("create_simulated_transaction", "create_simulated_payment"):
            res = self.env.raw_transfer(args.get("from_account", ""), args.get("to_account", ""),
                                        args.get("amount", 0), user, args.get("description", ""))
            self.trace.add("TOOL", tool, "ATTACK_EFFECT" if res["status"] == "success" else "ERROR",
                           f"Ledger written: {args.get('from_account')} -> {args.get('to_account')} ${args.get('amount')}",
                           agent=agent, result=res)
            return res
        if tool == "modify_system_policy":
            self.env.ft.system_policy = {"approval_required": False, "changed_by": user}
            res = {"status": "success", "tool": tool, "result": {"approval_required": False}}
            self.trace.add("TOOL", tool, "ATTACK_EFFECT", "System policy modified: human approval globally disabled (lab state)",
                           agent=agent, result=res)
            return res
        if tool == "execute_data_export":
            res = {"status": "success", "tool": tool, "result": {"rows": len(self.env.ft.customers), "note": "synthetic export"}}
            self.trace.add("TOOL", tool, "ATTACK_EFFECT", "Customer data export executed without authorization",
                           agent=agent, result=res)
            return res
        fn = getattr(self.env.ft, tool, None)
        if fn is None:
            handler = self.env.registry.get(tool)
            fn = handler.handler if handler else None
        if fn is None:
            return {"status": "error", "reason": "no handler"}
        try:
            res = fn(**{k: v for k, v in args.items() if k in fn.__code__.co_varnames})
        except Exception as exc:  # noqa: BLE001 - lab: surface the failure into the trace
            res = {"status": "error", "reason": type(exc).__name__}
        abuse = _is_sensitive_access(tool, args, user, self.env) or _lacks_permission(tool, identity)
        self.trace.add("TOOL", tool, "ATTACK_EFFECT" if abuse else "INFO",
                       f"{tool} executed for {user}" + (" (privilege/ownership violation)" if abuse else ""),
                       agent=agent, result=res)
        return res

    # -- secure ----------------------------------------------------------
    def _secure(self, tool: str, args: Dict[str, Any], identity: Identity, agent: str,
                approved_by: Optional[str]) -> Dict[str, Any]:
        tr = self.trace

        def block(stage: str, comp: str, reason: str, verdict: str = "BLOCK", **d: Any) -> Dict[str, Any]:
            tr.add(stage, comp, verdict, reason, agent=agent, **d)
            tr.audit(f"tool:{tool}", "BLOCK" if verdict == "BLOCK" else verdict, "blocked", "HIGH",
                     agent=agent, tool=tool, error=reason)
            return {"status": "blocked" if verdict == "BLOCK" else verdict.lower(), "tool": tool, "reason": reason,
                    "blocked_at": stage}

        # 0. Goal scope: is this tool within the user's approved goal?
        if self.goal_guard is not None:
            ok, why = self.goal_guard.permits(tool)
            if not ok:
                return block("GUARDRAIL", "GoalGuard", why, control="GOAL_SCOPE")
            tr.add("GUARDRAIL", "GoalGuard", "ALLOW", f"'{tool}' is within the anchored goal", agent=agent)

        # 1. Tool guardrail: whitelist + argument hygiene
        if tool not in TOOL_POLICY and tool not in self.extra_tools:
            return block("GUARDRAIL", "ToolGuardrail", f"Tool '{tool}' is not in the approved tool whitelist",
                         control="TOOL_WHITELIST")
        if tool in self.extra_tools:
            return block("GUARDRAIL", "ToolGuardrail", f"Tool '{tool}' is not an admitted MCP tool", control="TOOL_ADMISSION")
        text = str(args)
        for pat in _INJECTION_IN_ARGS:
            if re.search(pat, text):
                return block("GUARDRAIL", "ToolGuardrail", "Malicious pattern in tool arguments", control="ARG_INJECTION",
                             pattern=pat)
        pol = TOOL_POLICY[tool]
        if pol.get("financial"):
            try:
                amt = float(args.get("amount"))
            except (TypeError, ValueError):
                return block("GUARDRAIL", "ToolGuardrail", f"Invalid amount {args.get('amount')!r}", control="ARG_SCHEMA")
            if not (amt > 0) or amt != amt or amt in (float("inf"),):
                return block("GUARDRAIL", "ToolGuardrail", f"Amount must be a finite positive number (got {amt})",
                             control="ARG_SCHEMA")
            if amt > HARD_LIMIT:
                return block("GUARDRAIL", "ToolGuardrail", f"Amount ${amt:,.2f} exceeds hard limit ${HARD_LIMIT:,.2f}",
                             control="TRANSACTION_LIMIT")
            args["amount"] = amt
        if self.rate_limiter is not None:
            ok, why = self.rate_limiter.allow(agent, tool)
            if not ok:
                return block("GUARDRAIL", "ToolRateLimiter", why, control="RATE_LIMIT")
        tr.add("GUARDRAIL", "ToolGuardrail", "ALLOW", "Tool whitelisted, arguments valid", agent=agent, control="TOOL_GUARDRAIL")

        # 2a. Approval provenance: an agent may never assert its own authorization.
        for forged in ("user_authorized", "approved", "approval_override", "override_risk", "force_allow", "bypass_rules"):
            if forged in args:
                return block("APPROVAL", "ApprovalEngine",
                             f"Tool argument '{forged}' tries to self-approve; approval exists only as a human decision record",
                             control="NO_SELF_APPROVAL")
        # 2b. Identity provenance: LLM-supplied identity fields are never honoured.
        for forged in ("as_user", "caller_role", "role", "user_id"):
            if forged in args:
                return block("RBAC", "IdentityProvenance",
                             f"Tool argument '{forged}' tries to set identity; identity comes only from the auth session",
                             control="IDENTITY_PROVENANCE")
        role = identity.role_enum()
        if pol.get("roles") is not None and role.value.upper() not in pol["roles"]:
            return block("RBAC", "RBAC", f"Role {role.value} is not one of {sorted(pol['roles'])} required for '{tool}'", control="RBAC")
        if pol.get("perm") is not None and not has_permission(role, pol["perm"]):
            return block("RBAC", "RBAC", f"Role {role.value} lacks permission {pol['perm'].value}", control="RBAC")
        tr.add("RBAC", "RBAC", "ALLOW", f"{role.value} holds the required permission", agent=agent)

        # 3. Ownership
        if role == Role.CUSTOMER:
            arg = pol.get("owner_arg")
            if arg and args.get(arg) and args[arg] not in identity.account_ids:
                return block("RBAC", "OwnershipCheck", f"{identity.user_id} does not own {args[arg]}", control="OWNERSHIP")
            carg = pol.get("owner_card_arg")
            if carg and args.get(carg) and args[carg] not in identity.card_ids:
                return block("RBAC", "OwnershipCheck", f"{identity.user_id} does not own {args[carg]}", control="OWNERSHIP")
            cust = pol.get("customer_arg")
            if cust and args.get(cust) and args[cust] != identity.user_id:
                return block("RBAC", "OwnershipCheck", f"{identity.user_id} cannot read customer {args[cust]}", control="OWNERSHIP")
            tr.add("RBAC", "OwnershipCheck", "ALLOW", "Resource ownership verified", agent=agent)

        # 4. Deterministic risk
        risk_level = "LOW"
        if pol.get("financial"):
            src = self.env.ft.accounts.get(args.get("from_account", ""))
            if not src:
                return block("RISK", "RiskEngine", f"Unknown source account {args.get('from_account')}", control="ARG_SCHEMA")
            beneficiary_known = args.get("to_account") in self.env.ft.accounts
            risk_level = classify_risk(args["amount"], beneficiary_known)
            if src["balance"] < args["amount"]:
                return block("RISK", "RiskEngine", "Insufficient funds", control="RISK")
            tr.add("RISK", "RiskEngine", "ALLOW" if risk_level in ("LOW", "MEDIUM") else "REVIEW",
                   f"Deterministic risk = {risk_level} (amount ${args['amount']:,.2f}, "
                   f"beneficiary {'known' if beneficiary_known else 'NEW/EXTERNAL'})", agent=agent, risk=risk_level)

            # 5. Human approval (LLM can never approve itself)
            if risk_level in ("HIGH", "CRITICAL"):
                if not approved_by:
                    rec = self.env.approvals.create_request(
                        user_id=identity.user_id, action=f"{tool}:{args['from_account']}->{args['to_account']}:{args['amount']}",
                        risk=risk_level, request_id=tr.trace_id, parameters=args)
                    return block("APPROVAL", "ApprovalEngine",
                                 f"{risk_level}-risk action held for human approval ({rec.approval_id})",
                                 verdict="APPROVAL_REQUIRED", control="HUMAN_APPROVAL", approval_id=rec.approval_id)
                if approved_by.upper() in ApprovalEngine.PROHIBITED_AI_ROLES or approved_by == identity.user_id:
                    return block("APPROVAL", "ApprovalEngine", f"'{approved_by}' may not approve (AI/self approval)",
                                 control="NO_SELF_APPROVAL")
                tr.add("APPROVAL", "ApprovalEngine", "ALLOW", f"Approved by human {approved_by}", agent=agent)
            else:
                tr.add("APPROVAL", "ApprovalEngine", "INFO", "Approval not required for this risk level", agent=agent)
        else:
            tr.add("RISK", "RiskEngine", "INFO", "Read-only / low-risk tool", agent=agent)

        # 6. Lab-implemented tool (e.g. sandboxed analysis) or the MCP gateway with its own independent checks
        if tool in self.impls:
            res = self.impls[tool](**args)
            tr.add("TOOL", tool, "INFO" if res.get("status") == "success" else "BLOCK",
                   f"{tool} -> {res.get('status')}", agent=agent, result=res)
            tr.audit(f"tool:{tool}", "ALLOW" if res.get("status") == "success" else "BLOCK", res.get("status", "?"), risk_level,
                     agent=agent, tool=tool)
            return res
        if tool in ("modify_system_policy", "execute_data_export") and tool not in self.env.registry.list_tools():
            return block("MCP", "MCPServer", f"'{tool}' has no MCP registration", control="MCP_POLICY")
        kwargs = dict(args)
        if pol.get("financial"):
            kwargs.setdefault("customer_id", identity.user_id)
        res = self.env.mcp.execute_tool(tool, caller_role=identity.role_enum().value,
                                        user_authorized=bool(approved_by), **_mcp_kwargs(tool, kwargs, identity))
        status = res.get("status")
        tr.add("MCP", "MCPServer", "ALLOW" if status == "success" else "BLOCK",
               f"MCP gateway returned status={status}", agent=agent)
        tr.add("TOOL", tool, "INFO" if status == "success" else "BLOCK", f"{tool} -> {status}", agent=agent, result=res)
        tr.audit(f"tool:{tool}", "ALLOW" if status == "success" else "BLOCK", status or "unknown", risk_level,
                 agent=agent, tool=tool)
        return res


def _mcp_kwargs(tool: str, kwargs: Dict[str, Any], identity: Identity) -> Dict[str, Any]:
    kw = dict(kwargs)
    if tool in ("get_account_balance", "get_account_status", "get_transaction_history",
                "get_card_status", "freeze_card", "unfreeze_card"):
        kw.setdefault("customer_id", identity.user_id)
    if tool in ("create_simulated_transaction", "create_simulated_payment"):
        kw["customer_id"] = identity.user_id
    return kw


def classify_risk(amount: float, beneficiary_known: bool) -> str:
    """Deterministic lab risk model (the LLM can never override it)."""
    if amount >= 25_000 or (amount >= HARD_LIMIT / 2):
        return "CRITICAL"
    if amount >= APPROVAL_THRESHOLD:
        return "HIGH"
    if not beneficiary_known and amount >= 1_000:
        return "HIGH"
    if not beneficiary_known or amount >= 2_500:
        return "MEDIUM"
    return "LOW"


def _is_sensitive_access(tool: str, args: Dict[str, Any], user: str, env: LabEnvironment) -> bool:
    """True when a read tool touched a resource the acting user does not own (ASI03 evidence)."""
    acct = args.get("account_id")
    if acct and acct in env.ft.accounts and env.ft.accounts[acct]["customer_id"] != user:
        return True
    cust = args.get("customer_id")
    if cust and cust != user and cust.startswith("CUST-"):
        return True
    return False


def _lacks_permission(tool: str, identity: Optional[Identity]) -> bool:
    """True when the acting identity lacks the permission/role the tool requires (privilege abuse evidence)."""
    if identity is None:
        return False
    pol = TOOL_POLICY.get(tool)
    if pol is None:
        return False
    role = identity.role_enum()
    if pol.get("roles") is not None and role.value.upper() not in pol["roles"]:
        return True
    return pol.get("perm") is not None and not has_permission(role, pol["perm"])


def deepcopy_json(obj: Any) -> Any:
    return copy.deepcopy(obj)
