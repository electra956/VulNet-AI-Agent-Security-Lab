"""
VulNet AI Agent Security Lab - Central Security Controller
Provides security policies, telemetry events, multi-vector threat detection,
and controlled safe simulation for OWASP Agentic AI security scenarios.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class SecurityEvent:
    """Standardized Security Event Telemetry Schema."""
    timestamp: str
    event_type: str        # e.g., REQUEST_EVALUATION, CONTEXT_INSPECTION, TOOL_VALIDATION, INTER_AGENT_CHECK
    severity: str          # INFO, WARNING, HIGH, CRITICAL, BLOCKED
    scenario: Optional[str]  # e.g., ASI01 - Agent Goal Hijack, ASI02 - Tool Misuse, etc.
    component: str         # SECURITY_CONTROLLER, RAG, MAIN_AGENT, RESEARCH_AGENT, ACTION_AGENT, MCP
    message: str
    decision: str          # ALLOW, BLOCK, MITIGATE, AUDIT
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the event to dictionary format."""
        return asdict(self)


class SecurityController:
    """
    Central security controller for the VulNet AI Agent Security Lab.

    Features:
    - Secure Mode (strict enforcement, threat blocking, least-privilege verification)
    - Vulnerable Mode (controlled educational simulation of OWASP Agentic risks)
    - Multi-vector threat detection (User request, RAG context, Inter-agent messages, Tool outputs)
    - Structured telemetry events conforming to the lab standard
    """

    # Direct Goal Hijacking & Prompt Injection Heuristic Patterns (ASI01)
    GOAL_HIJACK_PATTERNS = [
        "ignore previous instructions",
        "ignore all previous instructions",
        "forget your instructions",
        "change your goal",
        "override your rules",
        "reveal system prompt",
        "reveal your prompt",
        "system prompt override",
        "execute this instruction",
        "you are now",
        "new role:",
        "bypass safety",
        "jailbreak",
        "disregard safety guidelines",
        "new objective:",
        "drop your objective",
        "dump system credentials",
        "dump credentials",
        "dump all customer tokens",
        "dump all credentials"
    ]

    # Tool Misuse and Exploitation Heuristics (ASI02)
    TOOL_MISUSE_PATTERNS = [
        "drop table",
        "; --",
        "; —",
        "; –",
        "execute high risk",
        "high risk system configuration",
        "unauthorized tool",
        "chmod",
        "rm -rf",
        "/etc/passwd",
        "curl http",
        "wget http",
        "execute_data_export"
    ]

    # Identity and Privilege Abuse Heuristics (ASI03)
    PRIVILEGE_ESCALATION_PATTERNS = [
        "unauthenticated guest",
        "disable mfa",
        "mfa enforcement",
        "grant admin",
        "grant me admin",
        "escalate privilege",
        "sudo",
        "assume role admin",
        "assume admin",
        "impersonate user",
        "set role=superuser",
        "override permission",
        "bypass role"
    ]

    # Unexpected Code Execution Heuristics (ASI05)
    CODE_EXECUTION_PATTERNS = [
        "python script:",
        "execute python script",
        "os.system",
        "subprocess",
        "__import__",
        "import os",
        "eval(",
        "exec(",
        "whoami"
    ]

    # Memory and Context Poisoning Heuristics (ASI06)
    MEMORY_POISONING_PATTERNS = [
        "forward all invoices",
        "attacker-controlled",
        "malicious-exfil",
        "poison memory",
        "http://malicious",
        "collector: http",
        "collector: https"
    ]

    def __init__(self, mode: str = "secure"):
        self.mode = mode.lower()
        if self.mode not in ["secure", "vulnerable"]:
            raise ValueError("Mode must be 'secure' or 'vulnerable'.")
        from security.security_gateway import SecurityGateway
        self.gateway = SecurityGateway(mode=self.mode)
        self.events: List[Dict[str, Any]] = []
        self.log_event(
            event_type="SYSTEM_INIT",
            message=f"Security Controller initialized in {self.mode.upper()} mode.",
            severity="INFO",
            component="SECURITY_CONTROLLER",
            decision="ALLOW"
        )

    def set_mode(self, mode: str) -> None:
        """Switch between Secure and Vulnerable operational modes."""
        mode_clean = mode.lower()
        if mode_clean not in ["secure", "vulnerable"]:
            raise ValueError("Mode must be 'secure' or 'vulnerable'.")
        self.mode = mode_clean
        if hasattr(self, "gateway"):
            self.gateway.set_mode(mode_clean)
        self.log_event(
            event_type="MODE_CHANGE",
            message=f"Security mode changed to: {self.mode.upper()}",
            severity="INFO",
            component="SECURITY_CONTROLLER",
            decision="ALLOW",
            metadata={"new_mode": self.mode}
        )

    def get_mode(self) -> str:
        """Get the current operational mode."""
        return self.mode

    def log_event(
        self,
        event_type: str,
        message: str,
        severity: str = "INFO",
        scenario: Optional[str] = None,
        component: str = "SECURITY_CONTROLLER",
        decision: str = "ALLOW",
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Record a structured security telemetry event."""
        event = SecurityEvent(
            timestamp=datetime.now().isoformat(),
            event_type=event_type,
            severity=severity,
            scenario=scenario,
            component=component,
            message=message,
            decision=decision,
            metadata=metadata or {}
        )
        event_dict = event.to_dict()
        # Maintain backwards compatibility: include 'type' alias for existing code
        event_dict["type"] = event_type
        self.events.append(event_dict)
        return event_dict

    def get_events(self) -> List[Dict[str, Any]]:
        """Retrieve all recorded security events."""
        return self.events

    def clear_events(self) -> None:
        """Clear recorded security events."""
        self.events = []

    def evaluate_request(self, user_request: str, session_context: Optional[Any] = None) -> Dict[str, Any]:
        """
        Evaluate incoming user request for multi-vector agentic threats (ASI01, ASI02, ASI03, ASI05, ASI06).
        Delegates to the AI Security Gateway while maintaining structured event telemetry.
        """
        decision_dict = self.gateway.evaluate(user_request, session_context=session_context, mode=self.mode)
        ctx_meta = decision_dict.get("session_context", {})

        if decision_dict["blocked"]:
            meta = {
                "detected_pattern": decision_dict.get("detected_pattern"),
                "mode": self.mode,
                "category": decision_dict.get("category"),
                "risk": decision_dict.get("risk"),
            }
            meta.update(ctx_meta)
            self.log_event(
                event_type="THREAT_BLOCKED" if decision_dict.get("scenario") else "REQUEST_EVALUATION",
                message=f"Protection blocked suspicious instruction: '{decision_dict.get('detected_pattern')}'"
                if decision_dict.get("detected_pattern")
                else decision_dict.get("reason", "Request blocked."),
                severity="BLOCKED" if decision_dict.get("scenario") else "WARNING",
                scenario=decision_dict.get("scenario"),
                component="SECURITY_CONTROLLER",
                decision="BLOCK",
                metadata=meta
            )
        elif decision_dict.get("is_simulation"):
            meta = {
                "detected_pattern": decision_dict.get("detected_pattern"),
                "mode": "vulnerable",
                "simulation": True,
                "category": decision_dict.get("category"),
                "risk": decision_dict.get("risk"),
            }
            meta.update(ctx_meta)
            self.log_event(
                event_type="VULNERABILITY_SIMULATION",
                message=f"Suspicious instruction detected but allowed in Vulnerable Mode: '{decision_dict.get('detected_pattern')}'",
                severity="WARNING",
                scenario=decision_dict.get("scenario"),
                component="SECURITY_CONTROLLER",
                decision="ALLOW",
                metadata=meta
            )
        elif decision_dict.get("requires_approval"):
            meta = {
                "category": decision_dict.get("category"),
                "risk": decision_dict.get("risk"),
            }
            meta.update(ctx_meta)
            self.log_event(
                event_type="APPROVAL_REQUIRED",
                message=decision_dict.get("reason", "Action requires approval."),
                severity="MEDIUM",
                scenario=decision_dict.get("scenario"),
                component="SECURITY_CONTROLLER",
                decision="APPROVAL",
                metadata=meta
            )
        else:
            clean_meta = {"request_preview": (user_request or "")[:80]}
            clean_meta.update(ctx_meta)
            self.log_event(
                event_type="REQUEST_EVALUATION",
                message="Request passed perimeter security validation.",
                severity="INFO",
                component="SECURITY_CONTROLLER",
                decision="ALLOW",
                metadata=clean_meta
            )

        return decision_dict



    def evaluate_context(self, context_text: str, source: str = "rag") -> Dict[str, Any]:
        """
        Inspect retrieved RAG or external context for indirect prompt injection (ASI01 / ASI06).
        """
        text_lower = context_text.lower()
        detected = None
        scenario = "ASI01 - Agent Goal Hijack"

        for pattern in self.GOAL_HIJACK_PATTERNS + self.TOOL_MISUSE_PATTERNS:
            if pattern in text_lower:
                detected = pattern
                break

        if not detected:
            for pattern in self.MEMORY_POISONING_PATTERNS:
                if pattern in text_lower:
                    detected = pattern
                    scenario = "ASI06 - Memory & Context Poisoning"
                    break

        if detected:
            if self.mode == "secure":
                self.log_event(
                    event_type="INDIRECT_INJECTION_DETECTED",
                    message=f"Suspicious context payload detected from source '{source}': '{detected}'. Neutralized in Secure Mode.",
                    severity="HIGH",
                    scenario=scenario,
                    component="RAG",
                    decision="MITIGATE",
                    metadata={"source": source, "pattern": detected}
                )
                return {"is_safe": False, "sanitized": True, "detected": detected}
            else:
                self.log_event(
                    event_type="INDIRECT_INJECTION_PASSTHROUGH",
                    message=f"Suspicious context payload detected from source '{source}': '{detected}'. Allowed in Vulnerable Mode.",
                    severity="WARNING",
                    scenario=scenario,
                    component="RAG",
                    decision="ALLOW",
                    metadata={"source": source, "pattern": detected}
                )
                return {"is_safe": False, "sanitized": False, "detected": detected}

        return {"is_safe": True, "sanitized": False, "detected": None}

    def evaluate_tool_authorization(
        self,
        tool_name: str,
        permission_level: str,
        risk_level: str,
        user_authorized: bool = False
    ) -> Dict[str, Any]:
        """
        Validate tool invocation authorization based on risk level and role (ASI02 & ASI03).
        """
        is_high_risk = risk_level.upper() in ["HIGH", "CRITICAL"]

        if self.mode == "secure":
            if is_high_risk and not user_authorized:
                self.log_event(
                    event_type="UNAUTHORIZED_TOOL_BLOCKED",
                    message=f"High-risk tool '{tool_name}' blocked: requires explicit authorization.",
                    severity="BLOCKED",
                    scenario="ASI02 - Tool Misuse and Exploitation",
                    component="MCP",
                    decision="BLOCK",
                    metadata={"tool": tool_name, "risk": risk_level}
                )
                return {
                    "allowed": False,
                    "reason": f"Tool '{tool_name}' has risk level {risk_level} and requires explicit authorization."
                }
            return {"allowed": True, "reason": "Tool authorization verified."}
        else:
            # Vulnerable Mode: simulate permission bypass safely
            if is_high_risk and not user_authorized:
                self.log_event(
                    event_type="SIMULATED_PERMISSION_BYPASS",
                    message=f"High-risk tool '{tool_name}' invoked without authorization in Vulnerable Mode.",
                    severity="WARNING",
                    scenario="ASI03 - Identity and Privilege Abuse",
                    component="MCP",
                    decision="ALLOW",
                    metadata={"tool": tool_name, "risk": risk_level, "simulation": True}
                )
            return {"allowed": True, "reason": "Allowed for educational simulation in Vulnerable Mode."}