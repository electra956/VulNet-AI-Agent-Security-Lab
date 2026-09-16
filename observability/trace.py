"""
VulNet FinTech AI Agent Security Lab - Agent Trace Subsystem.
Level 2 Step 15: Security Audit and Agent Trace.

Provides:
- End-to-end trace tracking for every request
- Complete 11-stage pipeline checklist formatting:
    Authentication        ✓
    Authorization         ✓
    Security Gateway      ✓
    Intent Classification ✓
    Main Agent            ✓
    Transaction Agent     ✓
    Risk Engine           ✓
    MCP                   ✓
    Permission            ✓
    Tool                  BLOCKED
    Audit                 ✓
- Automatic secret scrubbing (passwords, tokens, keys)
- Thread-safe trace repository for Streamlit telemetry & testing
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import threading
import time
from typing import Any, Dict, List, Optional

from observability.events import TraceStageName, StageStatus, TraceStageRecord
from observability.logger import redact_sensitive_data


# Standardized 11-stage pipeline order
STANDARD_TRACE_STAGES = [
    TraceStageName.AUTHENTICATION.value,
    TraceStageName.AUTHORIZATION.value,
    TraceStageName.SECURITY_GATEWAY.value,
    TraceStageName.INTENT_CLASSIFICATION.value,
    TraceStageName.MAIN_AGENT.value,
    TraceStageName.TRANSACTION_AGENT.value,  # Dynamically adapts to specialized agent name if different
    TraceStageName.RISK_ENGINE.value,
    TraceStageName.MCP.value,
    TraceStageName.PERMISSION.value,
    TraceStageName.TOOL.value,
    TraceStageName.AUDIT.value,
]


@dataclass
class AgentTrace:
    """
    Complete trace entity for a single request through the FinTech AI Agent pipeline.
    """
    request_id: str
    session_id: str
    user_id: str
    agent: Optional[str] = None
    tool: Optional[str] = None
    action: Optional[str] = None
    risk: str = "LOW"
    decision: str = "ALLOW"
    status: str = "completed"
    error: Optional[str] = None
    latency_ms: Optional[int] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    stages: List[TraceStageRecord] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def record_stage(
        self,
        stage_name: str,
        status: str = StageStatus.SUCCESS.value,
        details: Optional[str] = None,
        latency_ms: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> TraceStageRecord:
        """Add or update an individual stage execution record."""
        clean_meta = redact_sensitive_data(metadata or {})
        rec = TraceStageRecord(
            stage_name=stage_name,
            status=status,
            details=details,
            latency_ms=latency_ms,
            timestamp=datetime.now(timezone.utc).isoformat(),
            metadata=clean_meta
        )
        # Update existing stage if already present, else append
        for idx, existing in enumerate(self.stages):
            if existing.stage_name == stage_name:
                self.stages[idx] = rec
                return rec

        self.stages.append(rec)
        return rec

    def get_stage(self, stage_name: str) -> Optional[TraceStageRecord]:
        """Retrieve stage record by stage name."""
        for s in self.stages:
            if s.stage_name == stage_name:
                return s
        return None

    def render_checklist(self) -> str:
        """
        Renders the formatted 11-stage trace checklist matching specification:

        REQ-000123

        Authentication        ✓
        Authorization         ✓
        Security Gateway      ✓
        Intent Classification ✓
        Main Agent            ✓
        Transaction Agent     ✓
        Risk Engine           ✓
        MCP                   ✓
        Permission            ✓
        Tool                  BLOCKED
        Audit                 ✓
        """
        lines = [self.request_id, ""]

        # Map recorded stages for lookup
        stage_map = {s.stage_name: s.status for s in self.stages}

        # Build dynamic list of stages, replacing generic Transaction Agent if another agent ran
        active_agent_stage = self.agent or "Transaction Agent"
        if not active_agent_stage.endswith("Agent"):
            active_agent_stage = f"{active_agent_stage} Agent"

        pipeline_order = [
            "Authentication",
            "Authorization",
            "Security Gateway",
            "Intent Classification",
            "Main Agent",
            active_agent_stage,
            "Risk Engine",
            "MCP",
            "Permission",
            "Tool",
            "Audit"
        ]

        # Determine column width for neat alignment
        max_len = max(len(name) for name in pipeline_order) + 2

        for name in pipeline_order:
            # Check direct name or fallback to generic
            status = stage_map.get(name)
            if not status:
                # Try fallback for specialized agent stage
                if "Agent" in name and name not in ("Main Agent",):
                    for k, v in stage_map.items():
                        if "Agent" in k and k != "Main Agent":
                            name = k
                            status = v
                            break

            display_status = status if status else "SKIPPED"
            spacing = " " * (max_len - len(name))
            lines.append(f"{name}{spacing}{display_status}")

        return "\n".join(lines)

    def render_visual_trace(self) -> str:
        """
        Renders the clean hierarchical request trace visualization matching specification.

        Example (normal flow):
        REQ-001

        ✓ Authentication
        ✓ Security Gateway
        ✓ Customer Agent
        ✓ RAG
        ✓ MCP
        ✓ Tool
        ✓ Audit

        Example (blocked attack):
        REQ-002

        ✓ Authentication
        ✓ Security Gateway
        ✕ ASI01 BLOCK
        ○ Agents not executed
        """
        lines = [self.request_id, ""]
        stage_map = {s.stage_name: s for s in self.stages}

        # Check for blocked attack at perimeter / gateway
        gw_stage = stage_map.get("Security Gateway")
        is_gw_blocked = (
            (gw_stage and gw_stage.status == "BLOCKED")
            or (self.status == "blocked" and self.decision == "BLOCK" and (not self.agent or self.agent == "Security Controller"))
        )

        if is_gw_blocked:
            lines.append("✓ Authentication")
            lines.append("✓ Security Gateway")
            # Extract scenario code if present
            scenario_text = str(self.metadata.get("scenario") or (gw_stage.details if gw_stage else "") or self.error or "")
            asi_tag = "ASI01"
            for code in ("ASI01", "ASI02", "ASI03", "ASI04", "ASI05", "ASI06", "ASI07", "ASI08", "ASI09", "ASI10"):
                if code in scenario_text or code in str(self.metadata):
                    asi_tag = code
                    break
            lines.append(f"✕ {asi_tag} BLOCK")
            lines.append("○ Agents not executed")
            return "\n".join(lines)

        # Normal or downstream execution
        auth_status = "✓" if not stage_map.get("Authentication") or stage_map["Authentication"].status == "✓" else "✕"
        lines.append(f"{auth_status} Authentication")

        gw_status = "✓" if not gw_stage or gw_stage.status == "✓" else "✕"
        lines.append(f"{gw_status} Security Gateway")

        # Specialized Agent (e.g. Customer Agent, Transaction Agent)
        active_agent = self.agent or "Customer Agent"
        if not active_agent.endswith("Agent"):
            active_agent = f"{active_agent} Agent"
        lines.append(f"✓ {active_agent}")

        # RAG
        lines.append("✓ RAG")

        # MCP
        lines.append("✓ MCP")

        # Tool
        tool_stage = stage_map.get("Tool")
        if tool_stage and tool_stage.status == "BLOCKED":
            lines.append("✕ Tool BLOCKED")
        else:
            lines.append("✓ Tool")

        # Audit
        lines.append("✓ Audit")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the trace to a sanitized dictionary."""
        raw = {
            "request_id": self.request_id,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "agent": self.agent,
            "tool": self.tool,
            "action": self.action,
            "risk": self.risk,
            "decision": self.decision,
            "status": self.status,
            "error": self.error,
            "latency_ms": self.latency_ms,
            "timestamp": self.timestamp,
            "stages": [s.to_dict() for s in self.stages],
            "checklist": self.render_checklist(),
            "visual_trace": self.render_visual_trace(),
            "metadata": self.metadata,
        }
        return redact_sensitive_data(raw)


class RequestTracer:
    """
    Contextual execution tracker managing timing and stage progression for a single request.
    """

    def __init__(
        self,
        request_id: str,
        session_id: str,
        user_id: str,
        action: Optional[str] = None
    ):
        self.start_time = time.perf_counter()
        self.stage_start_times: Dict[str, float] = {}
        self.trace = AgentTrace(
            request_id=request_id,
            session_id=session_id,
            user_id=user_id,
            action=action
        )

    def start_stage(self, stage_name: str) -> None:
        """Mark start time for a pipeline stage."""
        self.stage_start_times[stage_name] = time.perf_counter()

    def record_stage(
        self,
        stage_name: str,
        status: str = StageStatus.SUCCESS.value,
        details: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> TraceStageRecord:
        """Record stage completion, calculating latency if start time was tracked."""
        latency_ms = None
        if stage_name in self.stage_start_times:
            elapsed = time.perf_counter() - self.stage_start_times.pop(stage_name)
            latency_ms = max(0, int(elapsed * 1000))

        return self.trace.record_stage(
            stage_name=stage_name,
            status=status,
            details=details,
            latency_ms=latency_ms,
            metadata=metadata
        )

    def finalize(
        self,
        status: Optional[str] = None,
        decision: Optional[str] = None,
        risk: Optional[str] = None,
        agent: Optional[str] = None,
        tool: Optional[str] = None,
        error: Optional[str] = None
    ) -> AgentTrace:
        """Compute final request latency and return the finalized trace entity."""
        total_latency = int((time.perf_counter() - self.start_time) * 1000)
        self.trace.latency_ms = total_latency

        if status:
            self.trace.status = status
        if decision:
            self.trace.decision = decision
        if risk:
            self.trace.risk = risk
        if agent:
            self.trace.agent = agent
        if tool:
            self.trace.tool = tool
        if error:
            self.trace.error = error

        return self.trace


class TraceStore:
    """Thread-safe storage for in-flight and historical traces."""

    def __init__(self, max_traces: int = 500):
        self._lock = threading.RLock()
        self._traces: List[AgentTrace] = []
        self._max_traces = max_traces

    def add_trace(self, trace: AgentTrace) -> None:
        """Store or update trace in the rolling trace store."""
        with self._lock:
            # Replace existing if present
            for i, t in enumerate(self._traces):
                if t.request_id == trace.request_id:
                    self._traces[i] = trace
                    return

            self._traces.append(trace)
            if len(self._traces) > self._max_traces:
                self._traces.pop(0)

    def get_trace(self, request_id: str) -> Optional[AgentTrace]:
        """Retrieve trace by request ID."""
        with self._lock:
            for t in self._traces:
                if t.request_id == request_id:
                    return t
            return None

    def list_traces(self, limit: int = 50) -> List[AgentTrace]:
        """Return the most recent traces in reverse chronological order."""
        with self._lock:
            return list(reversed(self._traces[-limit:]))

    def clear(self) -> None:
        """Reset traces."""
        with self._lock:
            self._traces.clear()


_global_trace_store: Optional[TraceStore] = None
_store_lock = threading.Lock()


def get_trace_store() -> TraceStore:
    """Retrieve or initialize singleton TraceStore."""
    global _global_trace_store
    with _store_lock:
        if _global_trace_store is None:
            _global_trace_store = TraceStore()
        return _global_trace_store
