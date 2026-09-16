"""
VulNet FinTech AI Agent Security Lab - Observability Events & Stage Definitions.
Defines standardized execution stages, status types, and telemetry event records.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class TraceStageName(str, Enum):
    """Standardized trace stage names matching enterprise pipeline architecture."""
    AUTHENTICATION = "Authentication"
    AUTHORIZATION = "Authorization"
    SECURITY_GATEWAY = "Security Gateway"
    INTENT_CLASSIFICATION = "Intent Classification"
    MAIN_AGENT = "Main Agent"
    TRANSACTION_AGENT = "Transaction Agent"
    CUSTOMER_AGENT = "Customer Agent"
    FRAUD_AGENT = "Fraud Agent"
    COMPLIANCE_AGENT = "Compliance Agent"
    SUPPORT_AGENT = "Support Agent"
    RESEARCH_AGENT = "Research Agent"
    SPECIALIZED_AGENT = "Specialized Agent"
    RISK_ENGINE = "Risk Engine"
    MCP = "MCP"
    PERMISSION = "Permission"
    TOOL = "Tool"
    AUDIT = "Audit"


class StageStatus(str, Enum):
    """Status outcomes for individual trace stages."""
    SUCCESS = "✓"
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"
    REQUIRED = "REQUIRED"
    PENDING = "PENDING"


@dataclass
class TraceStageRecord:
    """Record of an individual stage's execution within a request trace."""
    stage_name: str
    status: str  # "✓", "BLOCKED", "ERROR", "SKIPPED", etc.
    details: Optional[str] = None
    latency_ms: Optional[int] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage_name": self.stage_name,
            "status": self.status,
            "details": self.details,
            "latency_ms": self.latency_ms,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }
