"""Read-only catalogues used by the API and dashboard: MCP tools, agents, AIBOM, users, synthetic data."""

from __future__ import annotations

from typing import Any, Dict, List

from auth.users import get_default_users
from lab.bus import agent_manifests, build_agents
from lab.core import AttackTrace, CUSTOMER_001, LAB_LABEL, LabEnvironment, TOOL_POLICY, ToolGateway
from lab.supplychain import AdmissionController, build_inventory
from mcp_server.tools import create_default_registry


def tools_catalog() -> List[Dict[str, Any]]:
    """Every MCP tool with schema, risk, owner, trust level and the permission/role it requires."""
    out = []
    for name, meta in sorted(create_default_registry().get_all_metadata().items()):
        pol = TOOL_POLICY.get(name, {})
        perm = pol.get("perm")
        meta = dict(meta)
        meta["required_permissions"] = [perm.value] if perm is not None else (sorted(pol["roles"]) if pol.get("roles") else meta.get("required_permissions", []))
        out.append(meta)
    return out


def agents_catalog() -> Dict[str, Dict[str, Any]]:
    env = LabEnvironment("secure")
    tr = AttackTrace("CATALOG", "secure")
    return agent_manifests(build_agents(env, ToolGateway(env, tr, "secure"), tr, CUSTOMER_001, include_rogue=True))


def aibom_catalog() -> List[Dict[str, Any]]:
    ac = AdmissionController()
    rows = []
    for c in build_inventory():
        f = ac.check(c)
        rows.append({**c.to_aibom(), "admission": ac.decision(f), "findings": [x.control for x in f]})
    return rows


def users_catalog() -> List[Dict[str, Any]]:
    return [{"user_id": u.user_id, "username": u.username, "name": u.full_name, "role": u.role.upper(),
             "accounts": u.account_ids, "mfa": u.mfa_enabled, "status": u.status} for u in get_default_users().values()]


def synthetic_data() -> Dict[str, Any]:
    env = LabEnvironment("secure")
    ft = env.ft
    return {"label": LAB_LABEL, "customers": list(ft.customers.values()), "accounts": list(ft.accounts.values()),
            "cards": list(ft.cards.values()), "transactions": ft.transactions, "fraud_cases": list(ft.fraud_cases.values()),
            "support_tickets": list(ft.support_tickets.values())}
