"""
VulNet FinTech AI Agent Security Lab - Memory Validator
Provides deterministic security boundaries for prospective agent memories:
- Classifies candidate memories into: SAFE, SENSITIVE, UNTRUSTED, REJECTED
- Enforces the golden FinTech invariant: Memory must NEVER become an authorization mechanism.
- Defends against ASI06 Memory Poisoning, prompt injection, and credential exfiltration.
"""

from enum import Enum
import re
from typing import Any, Dict, Optional, Tuple


class MemoryClassification(str, Enum):
    SAFE = "SAFE"
    SENSITIVE = "SENSITIVE"
    UNTRUSTED = "UNTRUSTED"
    REJECTED = "REJECTED"


class MemoryValidator:
    """
    Validates prospective memory items before persistence to prevent memory poisoning (ASI06),
    privilege escalation, and unauthorized permission retention.

    CORE FINTECH INVARIANTS:
    1. Memory is strictly a passive data store for conversation context and benign user preferences.
    2. Memory must NEVER be an authorization authority. Any memory claiming authorization,
       entitlement, role escalation, or account access override is REJECTED immediately.
    3. Credentials, unmasked payment cards, and SSNs are classified as SENSITIVE and redacted.
    4. Exfiltration URLs, scripts, and prompt injections are REJECTED.
    """

    # 1. Authorization claim patterns that must NEVER be stored as memory
    AUTHORIZATION_CLAIM_PATTERNS = [
        r"(?i)\b(i am authorized|i have permission|grant(?:ed)? me access|authorize me to)\b",
        r"(?i)\b(transfer money from all accounts|access all accounts|bypass authorization)\b",
        r"(?i)\b(i am (?:an? )?(?:admin|administrator|manager|auditor|fraud analyst))\b",
        r"(?i)\b(my role is (?:admin|administrator|manager|auditor))\b",
        r"(?i)\b(set my role to|elevate my (?:role|privileges|permissions))\b",
        r"(?i)\b(remember that i (?:can|am allowed to|have rights to))\b",
        r"(?i)\b(allow (?:me|all transfers) without (?:secondary )?approval)\b",
        r"(?i)\b(override (?:policy|rules|guardrails|authorization))\b"
    ]

    # 2. Poisoning and prompt injection patterns (ASI06 / ASI01)
    POISONING_PATTERNS = [
        r"(?i)(ignore (?:all )?previous instructions|forget your instructions)",
        r"(?i)(new objective:|change your goal to|system prompt override)",
        r"(?i)(http://|https://|ftp://|webhook|attacker\.local)",
        r"(?i)(forward all (?:invoices|emails|data) to)",
        r"(?i)(<script|javascript:|eval\(|subprocess)",
        r"(?i)(export the complete customer database)"
    ]

    # 3. Sensitive data patterns (PII, credentials, payment data)
    SENSITIVE_PATTERNS = [
        (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
        (r"\b(?:\d{4}[- ]?){3}\d{4}\b", "[REDACTED_CARD]"),
        (r"(?i)\b(password|passwd|secret_key|api_key|private_key)\s*[:=]\s*\S+", "[REDACTED_CREDENTIAL]"),
        (r"(?i)\b(pin\s*[:=]\s*\d{4,6})\b", "[REDACTED_PIN]")
    ]

    def validate_memory(
        self,
        key: str,
        value: Any,
        memory_type: str = "preference"
    ) -> Dict[str, Any]:
        """
        Validate and classify prospective memory item.

        Returns:
            {
                "classification": "SAFE" | "SENSITIVE" | "UNTRUSTED" | "REJECTED",
                "is_allowed": bool,
                "reason": str,
                "sanitized_value": Any,
                "rejected_pattern": Optional[str]
            }
        """
        str_key = str(key).strip()
        str_val = str(value).strip() if value is not None else ""
        combined_text = f"{str_key} {str_val}".strip()

        # ----------------------------------------------------
        # STAGE 1: Check for Authorization Claims (REJECTED)
        # ----------------------------------------------------
        for pattern in self.AUTHORIZATION_CLAIM_PATTERNS:
            match = re.search(pattern, combined_text)
            if match:
                return {
                    "classification": MemoryClassification.REJECTED.value,
                    "is_allowed": False,
                    "reason": (
                        "Memory rejected: Unauthorized authorization claim detected. "
                        "Memory must never become an authorization mechanism."
                    ),
                    "sanitized_value": None,
                    "rejected_pattern": match.group(0)
                }

        # ----------------------------------------------------
        # STAGE 2: Check for Memory Poisoning / Injection (REJECTED)
        # ----------------------------------------------------
        for pattern in self.POISONING_PATTERNS:
            match = re.search(pattern, combined_text)
            if match:
                return {
                    "classification": MemoryClassification.REJECTED.value,
                    "is_allowed": False,
                    "reason": (
                        f"Memory rejected: Detected adversarial poisoning or injection directive: '{match.group(0)}'."
                    ),
                    "sanitized_value": None,
                    "rejected_pattern": match.group(0)
                }

        # ----------------------------------------------------
        # STAGE 3: Check for Sensitive Data (SENSITIVE -> REDACTED)
        # ----------------------------------------------------
        sanitized_val = str_val
        has_sensitive_data = False
        for pattern, replacement in self.SENSITIVE_PATTERNS:
            if re.search(pattern, sanitized_val):
                sanitized_val = re.sub(pattern, replacement, sanitized_val)
                has_sensitive_data = True

        if has_sensitive_data:
            return {
                "classification": MemoryClassification.SENSITIVE.value,
                "is_allowed": True,
                "reason": "Memory accepted with sensitive PII/credentials redacted.",
                "sanitized_value": sanitized_val,
                "rejected_pattern": None
            }

        # ----------------------------------------------------
        # STAGE 4: Check for Untrusted External Context (UNTRUSTED)
        # ----------------------------------------------------
        if any(w in str_key.lower() for w in ["untrusted", "third_party", "external", "user_upload"]):
            return {
                "classification": MemoryClassification.UNTRUSTED.value,
                "is_allowed": True,
                "reason": "Memory accepted but tagged as UNTRUSTED external provenance.",
                "sanitized_value": str_val,
                "rejected_pattern": None
            }

        # ----------------------------------------------------
        # STAGE 5: Safe Benign Memory (SAFE)
        # ----------------------------------------------------
        return {
            "classification": MemoryClassification.SAFE.value,
            "is_allowed": True,
            "reason": "Memory item validated successfully as safe context.",
            "sanitized_value": str_val if isinstance(value, str) else value,
            "rejected_pattern": None
        }
