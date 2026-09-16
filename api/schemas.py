"""
VulNet FinTech AI Agent Security Lab - API Gateway Schemas.
Level 2 Step 4: FastAPI API Gateway.

Provides Pydantic models for request/response validation, input sanitization,
and structured error reporting.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class HealthResponse(BaseModel):
    """Health check endpoint response model."""
    status: str = Field("ok", description="Overall service status")
    service: str = Field("VulNet FinTech API Gateway", description="Service name")
    version: str = Field("2.0.0", description="API version")
    environment: str = Field("local_simulation", description="Runtime environment")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat(), description="ISO timestamp")
    components: Optional[Dict[str, str]] = Field(
        default_factory=lambda: {
            "security_controller": "active",
            "fintech_service": "active",
            "orchestrator": "active",
            "session_manager": "active",
        },
        description="Individual subsystem health statuses"
    )


class ChatRequest(BaseModel):
    """Chat message request model with strict validation."""
    message: str = Field(..., min_length=1, max_length=4000, description="User prompt or banking inquiry")
    session_id: Optional[str] = Field(None, max_length=100, description="Session ID for context preservation")
    user_id: Optional[str] = Field("CUST-001", max_length=50, description="Simulated customer ID")
    mode: Optional[str] = Field("secure", pattern="^(secure|vulnerable)$", description="Security mode")

    @field_validator("message")
    @classmethod
    def validate_message_not_blank(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("Message cannot be empty or whitespace only.")
        return stripped


class ChatResponse(BaseModel):
    """Standardized chat response model with correlated tracking."""
    request_id: str = Field(..., description="Correlated unique request ID")
    session_id: str = Field(..., description="Preserved session ID")
    status: str = Field(..., description="Execution status: completed, blocked, or error")
    response: str = Field(..., description="Assistant response payload or markdown")
    scenario: Optional[str] = Field(None, description="Triggered security scenario (e.g., ASI01)")
    decision: Optional[str] = Field(None, description="Security perimeter decision (ALLOW or BLOCK)")
    user_id: Optional[str] = Field(None, description="Associated customer identity")
    execution_time_ms: Optional[int] = Field(None, description="Execution latency in milliseconds")


class AccountResponse(BaseModel):
    """Simulated account detail response model."""
    account_id: str = Field(..., description="Simulated Account ID (e.g. ACC-1001)")
    customer_id: str = Field(..., description="Owner customer ID")
    balance: float = Field(..., description="Current available balance")
    currency: str = Field("USD", description="Currency ISO code")
    status: str = Field("ACTIVE", description="Account status")
    account_type: str = Field("CHECKING", description="Account type or tier")


class SecurityEvaluateRequest(BaseModel):
    """Security prompt inspection request model."""
    request_text: str = Field(..., min_length=1, max_length=4000, description="Text prompt to inspect for threats")
    session_id: Optional[str] = Field(None, max_length=100, description="Optional session context ID")
    user_id: Optional[str] = Field("CUST-001", max_length=50, description="Customer ID")
    mode: Optional[str] = Field("secure", pattern="^(secure|vulnerable)$", description="Security mode")

    @field_validator("request_text")
    @classmethod
    def validate_request_text_not_blank(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("request_text cannot be empty or blank.")
        return stripped


class SecurityEvaluateResponse(BaseModel):
    """Security prompt inspection response model."""
    request_id: str = Field(..., description="Correlated request ID")
    allowed: bool = Field(..., description="Whether request is permitted to proceed")
    blocked: bool = Field(..., description="Whether request was blocked at perimeter")
    decision: str = Field(..., description="Perimeter decision: ALLOW or BLOCK")
    reason: Optional[str] = Field(None, description="Explanation for security decision")
    scenario: Optional[str] = Field(None, description="OWASP Agentic AI threat category (e.g. ASI01)")
    detected_pattern: Optional[str] = Field(None, description="Matched threat heuristic pattern")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat(), description="Evaluation timestamp")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Sanitized telemetry metadata")


class ErrorResponse(BaseModel):
    """Sanitized API error response model."""
    detail: str = Field(..., description="Sanitized error description")
    request_id: Optional[str] = Field(None, description="Correlated request ID")
    status: str = Field("error", description="Error status indicator")


# ============================================================
# AUTHENTICATION SCHEMAS (LEVEL 2 STEP 5)
# ============================================================

class LoginRequest(BaseModel):
    """User login request model."""
    username: str = Field(..., min_length=1, max_length=100, description="Username or customer ID")
    password: str = Field(..., min_length=1, max_length=200, description="User password")

    @field_validator("username", "password")
    @classmethod
    def not_blank(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Field cannot be empty or blank.")
        return v.strip()


class LoginResponse(BaseModel):
    """MFA challenge response model after valid credentials."""
    status: str = Field("mfa_required", description="Authentication phase")
    challenge_id: str = Field(..., description="MFA Challenge ID for Step 2 verification")
    user_id: str = Field(..., description="Authenticated user identifier")
    role: str = Field(..., description="User role")
    expires_at: str = Field(..., description="Challenge expiration timestamp")
    mfa_code: Optional[str] = Field(None, description="Local lab test inspection code")


class MFAVerifyRequest(BaseModel):
    """MFA verification request model."""
    challenge_id: str = Field(..., min_length=3, max_length=50, description="MFA Challenge ID")
    code: str = Field(..., min_length=4, max_length=10, description="6-digit verification code")

    @field_validator("challenge_id", "code")
    @classmethod
    def not_blank(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Field cannot be empty or blank.")
        return v.strip()


class MFAVerifyResponse(BaseModel):
    """Authenticated session response model."""
    status: str = Field("authenticated", description="Authentication status")
    session_id: str = Field(..., description="Active authenticated session identifier")
    user_id: str = Field(..., description="User ID")
    role: str = Field(..., description="Role assigned to user")
    account_ids: List[str] = Field(default_factory=list, description="Authorized customer account IDs")
    authenticated_at: str = Field(..., description="Authentication timestamp")


class LogoutRequest(BaseModel):
    """Logout request model."""
    session_id: str = Field(..., min_length=1, max_length=100, description="Session ID to invalidate")


class LogoutResponse(BaseModel):
    """Logout response model."""
    status: str = Field("logged_out", description="Session state")
    session_id: str = Field(..., description="Invalidated session ID")


class SessionResponse(BaseModel):
    """Session inspection response model."""
    session_id: str
    user_id: str
    role: str
    account_ids: List[str]
    is_active: bool
    authenticated_at: str
