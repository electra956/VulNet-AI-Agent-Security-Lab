"""
VulNet FinTech AI Agent Security Lab - Health Route.
GET /health
"""

from datetime import datetime
from fastapi import APIRouter
from api.schemas import HealthResponse

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    """
    Returns system status and readiness of core FinTech AI Agent subsystems.
    """
    return HealthResponse(
        status="ok",
        service="VulNet FinTech API Gateway",
        version="2.0.0",
        environment="local_simulation",
        timestamp=datetime.now().isoformat(),
        components={
            "security_controller": "active",
            "fintech_service": "active",
            "orchestrator": "active",
            "session_manager": "active",
        }
    )
