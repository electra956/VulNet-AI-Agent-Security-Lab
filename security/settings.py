"""
VulNet FinTech AI Agent Security Lab - Runtime Settings.

Central, environment-driven switches that separate "lab conveniences" (client-selectable
vulnerable mode, MFA code shown in the login response) from production-like behaviour.

VULNET_ENV=local_lab (default) keeps the lab conveniences on.
VULNET_ENV=hardened forces them off; the flags below can only switch them off inside the lab.

Values are read on every call so tests and operators can change them at runtime.
"""

import os
from typing import List

try:  # load .env if python-dotenv is available; real environment variables win
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # pragma: no cover
    pass

LAB_ENV = "local_lab"
DEFAULT_CORS_ORIGINS = "http://localhost:8501,http://127.0.0.1:8501"


def _flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, "").strip() or default)
    except ValueError:
        return default


def environment() -> str:
    return (os.getenv("VULNET_ENV") or LAB_ENV).strip().lower()


def is_lab() -> bool:
    return environment() == LAB_ENV


def default_security_mode() -> str:
    """Server-side security mode. Clients cannot weaken it unless override is allowed."""
    mode = (os.getenv("SECURITY_MODE") or "secure").strip().lower()
    return mode if mode in {"secure", "vulnerable"} else "secure"


def allow_client_mode_override() -> bool:
    """May an authenticated client ask for vulnerable mode? Lab demo only."""
    return is_lab() and _flag("VULNET_ALLOW_MODE_OVERRIDE", True)


def expose_mfa_code() -> bool:
    """Return the MFA code in the /auth/login response (no SMS/email in the lab)."""
    return is_lab() and _flag("VULNET_EXPOSE_MFA_CODE", True)


def session_ttl_seconds() -> int:
    return _int("VULNET_SESSION_TTL_SECONDS", 1800)


def max_failed_logins() -> int:
    return _int("VULNET_MAX_FAILED_LOGINS", 5)


def lockout_seconds() -> int:
    return _int("VULNET_LOCKOUT_SECONDS", 900)


def cors_origins() -> List[str]:
    raw = os.getenv("VULNET_CORS_ORIGINS", DEFAULT_CORS_ORIGINS)
    return [o.strip() for o in raw.split(",") if o.strip()]


def llm_enabled() -> bool:
    """Use the local Ollama LLM for conversational replies (VULNET_USE_LLM=false forces the deterministic pipeline)."""
    return _flag("VULNET_USE_LLM", True)


def rag_embeddings_enabled() -> bool:
    """Use Ollama embeddings for RAG retrieval when available (VULNET_RAG_EMBEDDINGS=off keeps TF-IDF only)."""
    return (os.getenv("VULNET_RAG_EMBEDDINGS", "auto").strip().lower() not in {"off", "false", "0", "no"})
