"""
VulNet FinTech AI Agent Security Lab - API Client.
Provides HTTP communication between the Streamlit UI and the FastAPI API Gateway.
Supports graceful fallback if the gateway is offline or in embedded mode.
"""

import logging
from typing import Any, Dict, Optional
import httpx

logger = logging.getLogger("vulnet.chatbot.api_client")


class VulNetApiClient:
    """Client for communicating with the VulNet FastAPI Gateway."""

    def __init__(self, base_url: str = "http://127.0.0.1:8000", timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def check_health(self) -> Dict[str, Any]:
        """Check if FastAPI gateway is online and responding."""
        try:
            with httpx.Client(timeout=2.0) as client:
                res = client.get(f"{self.base_url}/health")
                if res.status_code == 200:
                    return {"available": True, "data": res.json()}
        except Exception:
            pass
        return {"available": False, "data": None}

    def post_chat(
        self,
        message: str,
        session_id: Optional[str] = None,
        user_id: str = "CUST-001",
        mode: str = "secure"
    ) -> Dict[str, Any]:
        """Send chat message to FastAPI POST /chat endpoint."""
        payload = {
            "message": message,
            "session_id": session_id,
            "user_id": user_id,
            "mode": mode
        }
        with httpx.Client(timeout=self.timeout) as client:
            res = client.post(f"{self.base_url}/chat", json=payload)
            if res.status_code in [200, 400, 403, 404, 422, 500]:
                return res.json()
            res.raise_for_status()
            return res.json()

    def get_account(self, account_id: str, customer_id: Optional[str] = None) -> Dict[str, Any]:
        """Retrieve account details via GET /account/{account_id}."""
        params = {}
        if customer_id:
            params["customer_id"] = customer_id
        with httpx.Client(timeout=self.timeout) as client:
            res = client.get(f"{self.base_url}/account/{account_id}", params=params)
            return res.json()

    def evaluate_security(
        self,
        request_text: str,
        session_id: Optional[str] = None,
        user_id: str = "CUST-001",
        mode: str = "secure"
    ) -> Dict[str, Any]:
        """Evaluate prompt via POST /security/evaluate."""
        payload = {
            "request_text": request_text,
            "session_id": session_id,
            "user_id": user_id,
            "mode": mode
        }
        with httpx.Client(timeout=self.timeout) as client:
            res = client.post(f"{self.base_url}/security/evaluate", json=payload)
            return res.json()

    def login(self, username: str, password: str) -> Dict[str, Any]:
        """Initiate login and MFA challenge via POST /auth/login."""
        payload = {"username": username, "password": password}
        with httpx.Client(timeout=self.timeout) as client:
            res = client.post(f"{self.base_url}/auth/login", json=payload)
            return res.json()

    def verify_mfa(self, challenge_id: str, code: str) -> Dict[str, Any]:
        """Complete MFA challenge via POST /auth/mfa/verify."""
        payload = {"challenge_id": challenge_id, "code": code}
        with httpx.Client(timeout=self.timeout) as client:
            res = client.post(f"{self.base_url}/auth/mfa/verify", json=payload)
            return res.json()

    def logout(self, session_id: str) -> Dict[str, Any]:
        """Invalidate session via POST /auth/logout."""
        payload = {"session_id": session_id}
        with httpx.Client(timeout=self.timeout) as client:
            res = client.post(f"{self.base_url}/auth/logout", json=payload)
            return res.json()
