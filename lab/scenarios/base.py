"""Shared scaffolding for the executable OWASP Agentic Top 10 scenarios."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from lab.controls import GoalGuard, IdentityAuthority
from lab.core import (AttackTrace, Identity, LabEnvironment, ScenarioResult, ToolGateway, CUSTOMER_001)
from lab.policy import CompromisedAgentPolicy, ContextBlock, PlanDecision


@dataclass
class Variant:
    id: str
    title: str
    description: str
    preconditions: str
    default_input: Any
    expected_vulnerable: str
    expected_secure: str
    control: str                                    # primary control expected to stop it
    runner: Callable[["RunCtx", Any, bool], Dict[str, Any]]


class Scenario:
    """One OWASP Agentic category: metadata + variants. Subclasses fill the class attributes."""
    id = ""
    name = ""
    owasp_text = ""
    variants: Dict[str, Variant] = {}

    @classmethod
    def list_variants(cls) -> List[Dict[str, Any]]:
        return [{"id": v.id, "title": v.title, "description": v.description, "preconditions": v.preconditions,
                 "default_input": v.default_input, "expected_vulnerable": v.expected_vulnerable,
                 "expected_secure": v.expected_secure, "control": v.control} for v in cls.variants.values()]

    @classmethod
    def run(cls, variant: str, mode: str, payload: Any = None, use_llm: bool = False) -> ScenarioResult:
        v = cls.variants[variant]
        ctx = RunCtx(cls.id, mode, variant)
        attack_input = copy.deepcopy(payload if payload not in (None, "") else v.default_input)
        try:
            out = v.runner(ctx, attack_input, use_llm) or {}
        except Exception as exc:  # noqa: BLE001 - a scenario must never crash the lab; record and fail closed
            ctx.trace.add("RESULT", "Scenario", "ERROR", f"scenario error: {type(exc).__name__}: {exc}")
            out = {"error": f"{type(exc).__name__}: {exc}"}
        return ctx.finalize(cls, v, attack_input, out)


class RunCtx:
    """Everything one scenario run needs: synthetic world, trace, identity, gateway."""

    def __init__(self, scenario_id: str, mode: str, variant: str, identity: Optional[Identity] = None):
        self.mode = mode.lower()
        self.scenario_id = scenario_id
        self.variant = variant
        self.env = LabEnvironment(self.mode)
        self.trace = AttackTrace(scenario_id, self.mode)
        ident = copy.deepcopy(identity or CUSTOMER_001)
        self.identity = IdentityAuthority.issue(ident) if self.mode == "secure" else ident
        self.trace.user_id = self.identity.user_id
        self.gw = ToolGateway(self.env, self.trace, self.mode)
        self.policy = CompromisedAgentPolicy(default_account=(self.identity.account_ids or ["ACC-1001"])[0])
        self.engine = "deterministic-policy"
        self.extra: Dict[str, Any] = {}

    @property
    def vulnerable(self) -> bool:
        return self.mode == "vulnerable"

    # -- trace helpers ---------------------------------------------------
    def attack_input(self, text: Any, channel: str) -> None:
        self.trace.add("ATTACK_INPUT", channel, "INFO", f"Attack delivered via {channel}", payload=text,
                       as_user=self.identity.user_id)

    def perimeter(self, text: str, assume_breach: bool = True) -> bool:
        """Run the real SecurityController input check. Returns True when the perimeter blocked the input."""
        ev = self.env.security.evaluate_request(text)
        blocked = ev.get("decision") == "BLOCK" or ev.get("blocked")
        if blocked and self.mode == "secure":
            self.trace.add("GUARDRAIL", "SecurityController", "BLOCK",
                           f"Perimeter blocked the input: {ev.get('reason', '')}", control="PERIMETER_INPUT_GUARDRAIL",
                           scenario=ev.get("scenario"), pattern=ev.get("detected_pattern"))
            self.trace.audit("perimeter_check", "BLOCK", "blocked", "HIGH", error=str(ev.get("reason")))
            if assume_breach:
                self.trace.add("AGENT", "Lab", "INFO",
                               "ASSUME-BREACH: the perimeter is bypassed on purpose so the deeper controls can be observed; "
                               "the agent is treated as fully compromised from here on")
            return True
        if ev.get("is_simulation"):
            self.trace.add("GUARDRAIL", "SecurityController", "ALLOW",
                           f"Vulnerable mode: threat detected but allowed for the simulation ({ev.get('detected_pattern')})")
        else:
            self.trace.add("GUARDRAIL", "SecurityController", "ALLOW", "Perimeter: no known injection signature")
        return False

    def plan(self, user_message: str, blocks: List[ContextBlock], use_llm: bool, goal: str = "") -> PlanDecision:
        self.policy.use_llm = use_llm
        d = self.policy.plan(user_message, blocks, original_goal=goal or user_message)
        # A tool call counts as a hijack only if it serves something other than the user's own goal. Calls that came
        # from the real LLM are judged against the goal derived from the user's message (a benign call is not an attack).
        allowed = GoalGuard(user_message).allowed
        hijacked = [c for c in d.calls
                    if c.obeyed_source not in ("user", "llm") or (c.obeyed_source == "llm" and c.tool not in allowed)]
        d.goal_changed = bool(hijacked)
        d.new_goal = f"{hijacked[0].tool} {hijacked[0].args}" if hijacked else None
        self.engine = d.engine
        self.trace.add("AGENT", "AgentPolicy", "ATTACK_EFFECT" if (d.goal_changed and self.vulnerable) else "INFO",
                       ("Agent goal hijacked: obeying " + ", ".join(sorted({c.obeyed_source for c in hijacked})))
                       if d.goal_changed else ("Agent plans " + (", ".join(c.tool for c in d.calls) or "no tool calls")),
                       engine=d.engine, original_goal=d.original_goal, planned=[c.tool for c in d.calls])
        return d

    def use_goal_guard(self, user_message: str) -> GoalGuard:
        g = GoalGuard(user_message)
        if self.mode == "secure":
            self.gw.goal_guard = g
            self.trace.add("AGENT", "GoalGuard", "INFO", f"Goal anchored from the authenticated user's message: '{g.goal}'",
                           goal=g.goal, allowed_tools=sorted(g.allowed))
        return g

    def run_calls(self, decision: PlanDecision, agent: str = "Agent", identity: Optional[Identity] = None) -> List[Dict[str, Any]]:
        results = []
        for c in decision.calls:
            results.append(self.gw.request(c.tool, dict(c.args), identity or self.identity, agent=agent))
        return results

    # -- result ----------------------------------------------------------
    def finalize(self, cls: type, v: Variant, attack_input: Any, out: Dict[str, Any]) -> ScenarioResult:
        tr = self.trace
        effect = tr.took_effect()
        blocked = tr.blocked_at()
        outcome = "ATTACK_SUCCEEDED" if effect else ("ATTACK_BLOCKED" if blocked else "NO_EFFECT")
        if out.get("error"):
            outcome = "ERROR"
        controls: List[str] = []
        for s in tr.steps:
            c = s.data.get("control")
            if c and s.verdict in ("BLOCK", "APPROVAL_REQUIRED", "REVIEW") and c not in controls:
                controls.append(c)
        blocked_by = None
        if blocked is not None:
            blocked_by = blocked.data.get("control") or blocked.component
        summary = out.pop("summary", "")
        if not summary:
            summary = ("Attack took effect inside the lab." if effect
                       else f"Attack stopped by {blocked_by}." if blocked else "Attack had no effect.")
        tr.add("RESULT", "Scenario", "INFO", summary, outcome=outcome)
        if not any(s.stage == "AUDIT" for s in tr.steps):
            tr.audit(f"scenario:{self.scenario_id}:{self.variant}", "ALLOW" if effect else "BLOCK", outcome.lower(),
                     "HIGH" if effect or blocked else "LOW")
        impact = {"ledger": self.env.ledger_diff()}
        impact.update(out.pop("impact", {}))
        return ScenarioResult(
            scenario_id=self.scenario_id, variant=v.id, mode=self.mode, title=v.title, attack_input=attack_input,
            steps=tr.to_list(), outcome=outcome, impact=impact, blocked_by=blocked_by, controls_observed=controls,
            evidence=out, trace_id=tr.trace_id, decision_engine=self.engine, summary=summary)
