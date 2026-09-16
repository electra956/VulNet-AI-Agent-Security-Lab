"""
VulNet FinTech AI Agent Security Lab - Simulated MFA Service.
Level 2 Step 5: Simulated Customer Authentication.

Provides:
- 6-digit MFA challenge generation.
- Time-bounded challenge expiration (default: 5 minutes).
- Attempt throttling (maximum 3 attempts).
- Constant-time code verification.
"""

from datetime import datetime, timedelta
import hmac
import secrets
from typing import Dict, Optional

from auth.models import MFAChallenge, MFAVerificationError


class MFAService:
    """
    Simulated Multi-Factor Authentication service for the local lab.
    """

    def __init__(self):
        self._challenges: Dict[str, MFAChallenge] = {}

    def create_challenge(self, user_id: str, expiry_seconds: int = 300) -> MFAChallenge:
        """
        Generate a unique MFA challenge and 6-digit code for the specified user.
        """
        chal_id = f"MFA-{secrets.token_hex(6).upper()}"
        code_num = secrets.randbelow(900_000) + 100_000
        code_str = f"{code_num:06d}"

        now = datetime.now()
        expires_at = (now + timedelta(seconds=expiry_seconds)).isoformat()

        challenge = MFAChallenge(
            challenge_id=chal_id,
            user_id=user_id,
            code=code_str,
            created_at=now.isoformat(),
            expires_at=expires_at,
            attempts=0,
            max_attempts=3,
            verified=False
        )
        self._challenges[chal_id] = challenge
        return challenge

    def get_challenge(self, challenge_id: str) -> Optional[MFAChallenge]:
        """Lookup an active challenge strictly by its ID."""
        return self._challenges.get(challenge_id)

    def verify_challenge(self, challenge_id: str, code: str) -> bool:
        """
        Verify the submitted 6-digit code against the challenge.
        Enforces expiration, attempt bounds, and timing-attack safe comparison.
        """
        challenge = self._challenges.get(challenge_id)
        if not challenge:
            raise MFAVerificationError(f"MFA Challenge '{challenge_id}' not found or invalid.")

        if challenge.verified:
            raise MFAVerificationError(f"MFA Challenge '{challenge_id}' has already been consumed.")

        now_dt = datetime.now()
        try:
            exp_dt = datetime.fromisoformat(challenge.expires_at)
        except Exception:
            exp_dt = now_dt

        if now_dt > exp_dt:
            raise MFAVerificationError(f"MFA Challenge '{challenge_id}' has expired. Please log in again.")

        challenge.attempts += 1
        if challenge.attempts > challenge.max_attempts:
            raise MFAVerificationError(f"Maximum MFA verification attempts exceeded for challenge '{challenge_id}'.")

        clean_code = code.strip()
        if not hmac.compare_digest(clean_code, challenge.code):
            raise MFAVerificationError("Invalid MFA verification code.")

        challenge.verified = True
        return True
