"""
VulNet FinTech AI Agent Security Lab - Threat Detector.
Level 2 Step 7: AI Security Gateway.

Provides multi-vector agentic threat scanning:
1. Direct Prompt Injection & Jailbreaking
2. Goal Hijacking & Role Manipulation (ASI01)
3. Tool-Related Threats & Parameter Injections (ASI02)
4. Privilege Escalation & Identity Spoofing (ASI03)
5. Unexpected Code Execution (ASI05)
6. Memory & Context Poisoning (ASI06)
7. Sensitive Data Requests (Exfiltration of tokens, passwords, credentials)
"""

from dataclasses import asdict, dataclass
import re
from typing import Dict, List, Optional


@dataclass
class ThreatFinding:
    """Detailed record of a detected threat."""
    category: str           # e.g., "ASI01", "ASI02", "ASI03", "ASI05", "ASI06", "SENSITIVE_DATA"
    scenario: str           # Human-readable scenario name
    pattern: str            # Matched trigger keyword or regex
    severity: str           # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    reason: str             # Clear rationale explaining the threat

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


class ThreatDetector:
    """
    Scans incoming requests and internal agent messages for adversarial patterns.
    """

    # 1. Goal Hijacking & Prompt Injection Patterns (ASI01)
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
        "disregard all previous rules",
        "do not follow your system prompt",
        "developer mode enabled",
    ]

    # 2. Sensitive Data Extraction Patterns
    SENSITIVE_DATA_PATTERNS = [
        "dump system credentials",
        "dump credentials",
        "dump all customer tokens",
        "dump all credentials",
        "dump passwords",
        "export all api keys",
        "reveal secret keys",
        "print customer ssn",
        "dump private keys",
        "exfiltrate tokens",
        "show all passwords",
        "dump all tokens",
    ]

    # 3. Tool Misuse & Parameter Injection Patterns (ASI02)
    TOOL_MISUSE_PATTERNS = [
        "drop table",
        "drop database",
        "; --",
        "; —",
        "; –",
        "' or 1=1",
        "\" or 1=1",
        "union select",
        "execute high risk",
        "high risk system configuration",
        "unauthorized tool",
        "chmod 777",
        "rm -rf",
        "/etc/passwd",
        "curl http",
        "wget http",
        "execute_data_export",
        "format disk",
    ]

    # 4. Identity and Privilege Abuse Patterns (ASI03)
    PRIVILEGE_ESCALATION_PATTERNS = [
        "unauthenticated guest",
        "disable mfa",
        "mfa enforcement",
        "grant admin",
        "grant me admin",
        "escalate privilege",
        "sudo ",
        "assume role admin",
        "assume admin",
        "impersonate user",
        "set role=superuser",
        "override permission",
        "bypass role",
    ]

    # 5. Unexpected Code Execution Patterns (ASI05)
    CODE_EXECUTION_PATTERNS = [
        "python script:",
        "execute python script",
        "os.system",
        "subprocess.popen",
        "subprocess.run",
        "__import__",
        "import os",
        "import sys",
        "eval(",
        "exec(",
        "whoami",
        "bash -c",
        "/bin/sh",
    ]

    # 6. Memory and Context Poisoning Patterns (ASI06)
    MEMORY_POISONING_PATTERNS = [
        "forward all invoices",
        "attacker-controlled",
        "malicious-exfil",
        "poison memory",
        "http://malicious",
        "collector: http",
        "collector: https",
    ]

    def scan(self, text: str) -> List[ThreatFinding]:
        """
        Execute comprehensive threat scanning across all vector categories.
        Returns a list of ThreatFinding objects (ordered by risk).
        """
        if not text:
            return []

        findings: List[ThreatFinding] = []
        lower_text = text.lower()

        # 1. Goal Hijacking Detection (ASI01)
        for pattern in self.GOAL_HIJACK_PATTERNS:
            if pattern in lower_text:
                findings.append(ThreatFinding(
                    category="ASI01",
                    scenario="ASI01 - Agent Goal Hijack",
                    pattern=pattern,
                    severity="CRITICAL",
                    reason=f"Goal hijacking or prompt injection pattern detected: '{pattern}'."
                ))
                break

        # 2. Sensitive Data Extraction Detection
        for pattern in self.SENSITIVE_DATA_PATTERNS:
            if pattern in lower_text:
                findings.append(ThreatFinding(
                    category="SENSITIVE_DATA",
                    scenario="ASI01 - Sensitive Data Exfiltration",
                    pattern=pattern,
                    severity="CRITICAL",
                    reason=f"Attempted exfiltration of sensitive credentials or tokens: '{pattern}'."
                ))
                break

        # 3. Tool Misuse & Injection Detection (ASI02)
        for pattern in self.TOOL_MISUSE_PATTERNS:
            if pattern in lower_text:
                findings.append(ThreatFinding(
                    category="ASI02",
                    scenario="ASI02 - Tool Misuse and Exploitation",
                    pattern=pattern,
                    severity="HIGH",
                    reason=f"Tool misuse, destructive parameter, or command injection pattern: '{pattern}'."
                ))
                break

        # 4. Privilege Escalation Detection (ASI03)
        for pattern in self.PRIVILEGE_ESCALATION_PATTERNS:
            if pattern in lower_text:
                findings.append(ThreatFinding(
                    category="ASI03",
                    scenario="ASI03 - Identity and Privilege Abuse",
                    pattern=pattern,
                    severity="HIGH",
                    reason=f"Privilege escalation or role manipulation pattern detected: '{pattern}'."
                ))
                break

        # 5. Unexpected Code Execution (ASI05)
        for pattern in self.CODE_EXECUTION_PATTERNS:
            if pattern in lower_text:
                findings.append(ThreatFinding(
                    category="ASI05",
                    scenario="ASI05 - Unexpected Code Execution",
                    pattern=pattern,
                    severity="CRITICAL",
                    reason=f"Arbitrary code execution or system command invocation pattern: '{pattern}'."
                ))
                break

        # 6. Memory & Context Poisoning (ASI06)
        for pattern in self.MEMORY_POISONING_PATTERNS:
            if pattern in lower_text:
                findings.append(ThreatFinding(
                    category="ASI06",
                    scenario="ASI06 - Memory & Context Poisoning",
                    pattern=pattern,
                    severity="HIGH",
                    reason=f"Indirect context poisoning or malicious destination pattern: '{pattern}'."
                ))
                break

        return findings
