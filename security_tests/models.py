"""
VulNet AI Agent Security Lab - Prompt Injection Security Testing Models
Defines data structures for security test cases, results, and execution reports.
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class TestResultStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


class AttackCategory(str, Enum):
    """Official OWASP Top 10 for Agentic Applications (2026) categories."""
    ASI01 = "ASI01 - Agent Goal Hijack"
    ASI02 = "ASI02 - Tool Misuse & Exploitation"
    ASI03 = "ASI03 - Identity & Privilege Abuse"
    ASI04 = "ASI04 - Agentic Supply Chain Vulnerabilities"
    ASI05 = "ASI05 - Unexpected Code Execution (RCE)"
    ASI06 = "ASI06 - Memory & Context Poisoning"
    ASI07 = "ASI07 - Insecure Inter-Agent Communication"
    ASI08 = "ASI08 - Cascading Failures"
    ASI09 = "ASI09 - Human-Agent Trust Exploitation"
    ASI10 = "ASI10 - Rogue Agents"
    # Attack-technique groupings used by the prompt-injection suites (not OWASP categories)
    DIRECT = "Direct Prompt Injection"
    INDIRECT = "Indirect Context Injection"
    TOOL = "Tool/MCP Injection"
    EXFILTRATION = "Secret Exfiltration"


@dataclass
class SecurityTestResult:
    """Standardized Security Test Execution Result Schema."""
    test_id: str
    category: str
    attack: str
    result: str  # "PASS" or "FAIL"
    blocked: bool
    secret_exposed: bool
    unauthorized_tool_called: bool
    details: str
    evidence: str
    execution_time_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert test result to dictionary conforming strictly to specification."""
        return {
            "test_id": self.test_id,
            "category": self.category,
            "attack": self.attack,
            "result": self.result,
            "blocked": self.blocked,
            "secret_exposed": self.secret_exposed,
            "unauthorized_tool_called": self.unauthorized_tool_called,
            "details": self.details,
            "evidence": self.evidence,
        }


@dataclass
class SecurityTestCase:
    """Definition of a Prompt Injection / Adversarial Security Test Case."""
    test_id: str
    name: str
    category: AttackCategory
    attack_type: str  # "direct", "rag_indirect", "tool_mcp", "secret_exfil", etc.
    prompt: str
    description: str
    expected_blocked: bool = True
    canaries_to_protect: List[str] = field(default_factory=list)
    untrusted_rag_chunks: List[str] = field(default_factory=list)
    tool_calls_prohibited: List[str] = field(default_factory=list)
    session_user_id: str = "CUST-001"
    session_role: str = "customer"
    mode: str = "secure"
    original_task: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
