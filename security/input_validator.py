"""
VulNet FinTech AI Agent Security Lab - Input Validator.
Level 2 Step 7: AI Security Gateway.

Provides perimeter input sanitization, encoding verification, length constraint
enforcement, and control character neutralization before any downstream analysis.
"""

from dataclasses import dataclass, field
import re
from typing import List, Optional


@dataclass
class ValidationResult:
    """Outcome of input validation."""
    is_valid: bool
    sanitized_text: str
    error_message: Optional[str] = None
    flags: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "is_valid": self.is_valid,
            "sanitized_text": self.sanitized_text,
            "error_message": self.error_message,
            "flags": self.flags
        }


class InputValidator:
    """
    Validates and sanitizes raw user inputs prior to threat analysis.
    Prevents buffer flooding, null-byte injection, and malicious control characters.
    """

    def __init__(self, max_length: int = 5000):
        self.max_length = max_length

    def validate(self, text: Optional[str]) -> ValidationResult:
        """
        Validate and sanitize user input text.
        """
        flags: List[str] = []

        # 1. Null or empty check
        if text is None:
            return ValidationResult(
                is_valid=False,
                sanitized_text="",
                error_message="Request is empty."
            )

        if not isinstance(text, str):
            text = str(text)

        trimmed = text.strip()
        if not trimmed:
            return ValidationResult(
                is_valid=False,
                sanitized_text="",
                error_message="Request is empty."
            )

        # 2. Maximum length constraint
        if len(trimmed) > self.max_length:
            return ValidationResult(
                is_valid=False,
                sanitized_text=trimmed[:self.max_length],
                error_message=f"Request exceeds maximum permitted length ({self.max_length} characters).",
                flags=["EXCEEDS_MAX_LENGTH"]
            )

        # 3. Null byte detection and removal
        if "\x00" in trimmed:
            flags.append("NULL_BYTE_DETECTED")
            trimmed = trimmed.replace("\x00", "")

        # 4. Zero-width character detection (often used to obscure adversarial prompts)
        zero_width_chars = ["\u200b", "\u200c", "\u200d", "\ufeff"]
        has_zero_width = any(c in trimmed for c in zero_width_chars)
        if has_zero_width:
            flags.append("ZERO_WIDTH_OBSCURATION")
            for c in zero_width_chars:
                trimmed = trimmed.replace(c, "")

        # 5. Excessive control character sanitization (keep normal newlines and tabs)
        sanitized = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", "", trimmed)
        if len(sanitized) != len(trimmed):
            flags.append("CONTROL_CHARS_REMOVED")

        # 6. Re-check empty after sanitization
        if not sanitized.strip():
            return ValidationResult(
                is_valid=False,
                sanitized_text="",
                error_message="Request contained only invalid or non-printable characters.",
                flags=flags
            )

        return ValidationResult(
            is_valid=True,
            sanitized_text=sanitized,
            error_message=None,
            flags=flags
        )
