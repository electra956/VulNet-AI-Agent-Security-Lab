"""
VulNet FinTech AI Agent Security Lab - FastAPI API Gateway.
Level 2 Step 4: FastAPI API Gateway.

Target Architecture:
Streamlit
  ↓
FastAPI (api/main.py)
  ↓
Existing VulNet Backend (Agents, SecurityController, FinTech Service)

Security & Operational Invariants:
1. Strict input validation with Pydantic models.
2. Rejection of malformed requests.
3. Monotonic request ID generation and correlation.
4. Preserved session context isolation.
5. Zero internal exception / traceback leakage to clients.
6. Zero credential / secret logging.
"""

import logging
import sys
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api.routes import health, chat, account, security, auth
from chatbot.sessions.session_manager import SessionManager

# Configure sanitized logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
)
logger = logging.getLogger("vulnet.api")

# Create FastAPI application instance
app = FastAPI(
    title="VulNet FinTech AI Agent API Gateway",
    description="Secure API Gateway layer for VulNet FinTech AI Agent Security Lab (Level 2).",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS Middleware (Local Lab Simulation)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    """
    Ensure every incoming HTTP request is correlated with a unique request ID.
    Propagates X-Request-ID to downstream logs and response headers.
    """
    req_id = request.headers.get("X-Request-ID") or SessionManager.generate_request_id()
    request.state.request_id = req_id

    response = await call_next(request)
    response.headers["X-Request-ID"] = req_id
    return response


# ============================================================
# EXCEPTION HANDLERS (SECURITY: NO RAW TRACEBACK LEAKAGE)
# ============================================================

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Sanitized HTTP exception handling."""
    req_id = getattr(request.state, "request_id", SessionManager.generate_request_id())
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "status": "error",
            "request_id": req_id
        },
        headers={"X-Request-ID": req_id}
    )


HTTP_422 = getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", 422)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handles malformed requests and validation failures cleanly."""
    req_id = getattr(request.state, "request_id", SessionManager.generate_request_id())
    logger.warning("Rejected malformed request on %s [Req: %s]", request.url.path, req_id)
    return JSONResponse(
        status_code=HTTP_422,
        content={
            "detail": "Request validation failed. Please check payload formatting and constraints.",
            "errors": jsonable_encoder(exc.errors()),
            "status": "error",
            "request_id": req_id
        },
        headers={"X-Request-ID": req_id}
    )


@app.exception_handler(Exception)
async def generic_unhandled_exception_handler(request: Request, exc: Exception):
    """
    Global catch-all exception handler.
    Guarantees internal server exceptions, call stacks, or confidential symbols
    are NEVER exposed directly in HTTP response bodies.
    """
    req_id = getattr(request.state, "request_id", SessionManager.generate_request_id())
    # Log securely without logging credentials
    logger.error("Unhandled server exception on %s [Req: %s]: %s", request.url.path, req_id, type(exc).__name__)

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "An internal server error occurred. Please contact system administrator.",
            "status": "error",
            "request_id": req_id
        },
        headers={"X-Request-ID": req_id}
    )


# ============================================================
# INCLUDE API ROUTERS
# ============================================================
app.include_router(health.router)
app.include_router(auth.router)
app.include_router(chat.router)
app.include_router(account.router)
app.include_router(security.router)


@app.get("/", tags=["Root"])
def root():
    """Root entrypoint with gateway summary."""
    return {
        "service": "VulNet FinTech API Gateway",
        "version": "2.0.0",
        "documentation": "/docs",
        "endpoints": {
            "health": "GET /health",
            "auth_login": "POST /auth/login",
            "auth_mfa_verify": "POST /auth/mfa/verify",
            "auth_logout": "POST /auth/logout",
            "chat": "POST /chat",
            "account": "GET /account/{account_id}",
            "security_evaluate": "POST /security/evaluate"
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="127.0.0.1", port=8000, reload=True)
