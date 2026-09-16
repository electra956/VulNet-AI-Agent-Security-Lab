"""
VulNet FinTech AI Agent Security Lab - Security Route.
POST /security/evaluate
"""

import logging
from datetime import datetime
from fastapi import APIRouter, HTTPException, status

from api.schemas import SecurityEvaluateRequest, SecurityEvaluateResponse
from chatbot.sessions.session_manager import SessionManager, SessionContext
from security.security_controller import SecurityController

logger = logging.getLogger("vulnet.api.security")
router = APIRouter(tags=["Security"])

# Global controllers
_controllers = {
    "secure": SecurityController(mode="secure"),
    "vulnerable": SecurityController(mode="vulnerable"),
}


def get_security_controller(mode: str) -> SecurityController:
    return _controllers.get(mode.lower(), _controllers["secure"])


@router.post("/security/evaluate", response_model=SecurityEvaluateResponse)
def evaluate_security_prompt(request: SecurityEvaluateRequest) -> SecurityEvaluateResponse:
    """
    Evaluates a user prompt or agent instruction against OWASP Agentic AI threat signatures
    (ASI01 Goal Hijack, ASI02 Tool Injection, ASI03 Privilege Escalation).
    """
    req_id = SessionManager.generate_request_id()
    mode = (request.mode or "secure").lower()
    controller = get_security_controller(mode)

    try:
        session_ctx = SessionContext(
            session_id=request.session_id or "API-EVAL-SESSION",
            request_id=req_id,
            user_id=request.user_id or "CUST-001",
            role="customer",
            account_ids=["ACC-1001"],
            created_at=datetime.now().isoformat(),
            conversation_id="EVAL-CONV"
        )

        eval_res = controller.evaluate_request(request.request_text, session_context=session_ctx)

        blocked = eval_res.get("blocked", False) or eval_res.get("decision") == "BLOCK"
        allowed = eval_res.get("allowed", not blocked)
        decision = eval_res.get("decision") or ("BLOCK" if blocked else "ALLOW")
        scenario = eval_res.get("scenario")
        reason = eval_res.get("reason") or eval_res.get("message")
        detected_pattern = eval_res.get("detected_pattern")
        metadata = eval_res.get("metadata", {})

        return SecurityEvaluateResponse(
            request_id=req_id,
            allowed=allowed,
            blocked=blocked,
            decision=decision,
            reason=reason,
            scenario=scenario,
            detected_pattern=detected_pattern,
            timestamp=datetime.now().isoformat(),
            metadata=metadata
        )

    except Exception as exc:
        logger.error("Error during security evaluation: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to evaluate security rules for provided input."
        )
