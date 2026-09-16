"""
VulNet FinTech AI Agent Security Lab - Structured JSON Logger & Secret Sanitizer.
Level 2 Step 15: Security Audit and Agent Trace.

Provides:
- Machine-readable structured JSON logging
- Recursive sensitive data redaction (passwords, tokens, MFA codes, API keys, CVVs)
- File and stream formatting adhering to security auditing best practices
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Union


# Sensitive keys that must NEVER appear unmasked in logs or traces
SENSITIVE_KEY_PATTERNS: Set[str] = {
    "password",
    "passwd",
    "token",
    "access_token",
    "refresh_token",
    "session_token",
    "bearer",
    "secret",
    "api_key",
    "apikey",
    "mfa_code",
    "otp",
    "pin",
    "cvv",
    "cvc",
    "credit_card",
    "card_number",
    "pan",
    "authorization",
    "private_key",
    "auth_code",
}

# Regex patterns for sensitive values embedded within strings
SENSITIVE_VALUE_REGEXES = [
    (re.compile(r"(Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(password['\":\s=]+)[^\s,;&\"']+", re.IGNORECASE), r"\1[REDACTED_PASSWORD]"),
    (re.compile(r"\b(?:\d[ -]*?){13,16}\b"), "[REDACTED_CARD]"),
    (re.compile(r"\b\d{6}\b(?=.*(?:mfa|otp|code))", re.IGNORECASE), "[REDACTED_MFA]"),
]


def redact_sensitive_data(data: Any) -> Any:
    """
    Recursively sanitize dictionaries, lists, and strings to strip credentials,
    tokens, MFA codes, cards, and sensitive keys.
    """
    if isinstance(data, dict):
        sanitized: Dict[str, Any] = {}
        for key, value in data.items():
            k_lower = str(key).lower().replace("-", "_")
            if any(sens in k_lower for sens in SENSITIVE_KEY_PATTERNS):
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = redact_sensitive_data(value)
        return sanitized

    elif isinstance(data, list):
        return [redact_sensitive_data(item) for item in data]

    elif isinstance(data, tuple):
        return tuple(redact_sensitive_data(item) for item in data)

    elif isinstance(data, str):
        cleaned = data
        for pattern, replacement in SENSITIVE_VALUE_REGEXES:
            cleaned = pattern.sub(replacement, cleaned)
        return cleaned

    return data


class StructuredJsonFormatter(logging.Formatter):
    """
    Custom logging formatter that renders records as sanitized JSON strings.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include custom attributes if passed in extra
        if hasattr(record, "request_id"):
            log_entry["request_id"] = record.request_id
        if hasattr(record, "session_id"):
            log_entry["session_id"] = record.session_id
        if hasattr(record, "user_id"):
            log_entry["user_id"] = record.user_id
        if hasattr(record, "component"):
            log_entry["component"] = record.component
        if hasattr(record, "action"):
            log_entry["action"] = record.action
        if hasattr(record, "risk"):
            log_entry["risk"] = record.risk
        if hasattr(record, "decision"):
            log_entry["decision"] = record.decision
        if hasattr(record, "metadata") and isinstance(record.metadata, dict):
            log_entry["metadata"] = record.metadata

        # Strictly sanitize before serialization
        sanitized_entry = redact_sensitive_data(log_entry)
        return json.dumps(sanitized_entry, ensure_ascii=False)


def get_structured_logger(
    name: str = "vulnet.observability",
    log_file: Optional[Union[str, Path]] = None,
    level: int = logging.INFO
) -> logging.Logger:
    """
    Factory function for a structured JSON logger.
    Optionally attaches a FileHandler writing single-line JSON entries.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Avoid duplicate handlers if already configured
    if not any(isinstance(h.formatter, StructuredJsonFormatter) for h in logger.handlers):
        formatter = StructuredJsonFormatter()

        # Stream handler (console)
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

        # File handler if specified
        if log_file:
            path = Path(log_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(str(path), encoding="utf-8")
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

    return logger
