"""
VulNet Attack Lab API - run the executable OWASP Agentic Top 10 (2026) scenarios.

All scenarios run against a fresh, synthetic, in-process world. Nothing here reaches real systems.
Authentication is required; Vulnerable mode follows the same gate as /chat (VULNET_ALLOW_MODE_OVERRIDE).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from auth.authentication import get_auth_service
from auth.models import UnauthorizedError
from auth.roles import normalize_role
from lab import catalog
from lab.registry import list_scenarios, run_scenario
from lab.runner import run_all, run_test, summarize, write_reports
from security import settings

HTTP_422 = getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", 422)
logger = logging.getLogger("vulnet.api.lab")
router = APIRouter(prefix="/lab", tags=["Attack Lab"])


class LabRunRequest(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=128)
    scenario: str = Field(..., pattern=r"^ASI(0[1-9]|10)$")
    variant: str = Field(..., min_length=1, max_length=64)
    mode: str = Field("secure", pattern="^(secure|vulnerable)$")
    payload: Optional[Any] = None
    use_llm: bool = False


class LabSessionRequest(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=128)
    scenario: Optional[str] = Field(None, pattern=r"^ASI(0[1-9]|10)$")
    variant: Optional[str] = Field(None, max_length=64)
    use_llm: bool = False


MAX_PAYLOAD_CHARS = 20_000


def _auth(session_id: str):
    try:
        return get_auth_service().authenticate_request(session_id)
    except UnauthorizedError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Authentication required: {exc}")


@router.get("/scenarios")
def scenarios() -> Dict[str, Any]:
    return {"scenarios": list_scenarios()}


@router.post("/run")
def run(req: LabRunRequest) -> Dict[str, Any]:
    _auth(req.session_id)
    if req.payload is not None and len(str(req.payload)) > MAX_PAYLOAD_CHARS:
        raise HTTPException(status_code=getattr(status, "HTTP_413_CONTENT_TOO_LARGE", 413), detail=f"payload exceeds {MAX_PAYLOAD_CHARS} characters")
    if req.mode == "vulnerable" and not settings.allow_client_mode_override():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Vulnerable mode cannot be selected by clients in this environment.")
    try:
        return run_scenario(req.scenario, req.variant, req.mode, req.payload, req.use_llm).to_dict()
    except ValueError as exc:
        raise HTTPException(status_code=HTTP_422, detail=str(exc))


@router.post("/test")
def test(req: LabSessionRequest) -> Dict[str, Any]:
    _auth(req.session_id)
    if req.scenario and req.variant:
        try:
            return run_test(req.scenario, req.variant, use_llm=req.use_llm).to_dict()
        except KeyError:
            raise HTTPException(status_code=HTTP_422, detail="Unknown scenario/variant")
    recs = run_all(req.scenario, use_llm=req.use_llm)
    return {"summary": summarize(recs), "tests": [r.to_dict() for r in recs]}


@router.post("/report")
def report(req: LabSessionRequest) -> Dict[str, Any]:
    sess = _auth(req.session_id)
    if normalize_role(sess.role).value == "CUSTOMER":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Generating reports writes files and is limited to staff roles.")
    recs = run_all(req.scenario, use_llm=req.use_llm)
    return {"summary": summarize(recs), "files": write_reports(recs)}


@router.get("/tools")
def tools() -> Dict[str, Any]:
    return {"tools": catalog.tools_catalog()}


@router.get("/agents")
def agents() -> Dict[str, Any]:
    return {"agents": catalog.agents_catalog()}


@router.get("/aibom")
def aibom() -> Dict[str, Any]:
    return {"components": catalog.aibom_catalog()}
