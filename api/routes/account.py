"""
VulNet FinTech AI Agent Security Lab - Account Route.
GET /account/{account_id}
"""

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Path, Query, status

from api.schemas import AccountResponse
from fintech.models import (
    AccountNotFoundError,
    CustomerNotFoundError,
    UnauthorizedAccessError,
)
from fintech.service import FintechService

logger = logging.getLogger("vulnet.api.account")
router = APIRouter(tags=["Account"])

# Shared service instance
_fintech_service = FintechService()


def get_fintech_service() -> FintechService:
    return _fintech_service


@router.get("/account/{account_id}", response_model=AccountResponse)
def get_account_by_id(
    account_id: str = Path(
        ...,
        min_length=3,
        max_length=20,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Simulated Account ID (e.g. ACC-1001)"
    ),
    customer_id: Optional[str] = Query(
        None,
        min_length=3,
        max_length=20,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Optional customer ID for strict ownership authorization"
    )
) -> AccountResponse:
    """
    Retrieve simulated account details with programmatic ownership validation.
    If customer_id is specified, verifies that the customer owns the requested account.
    """
    clean_account_id = account_id.strip().upper()
    service = get_fintech_service()

    try:
        if customer_id:
            clean_cust_id = customer_id.strip().upper()
            account = service.get_account(clean_cust_id, clean_account_id)
        else:
            account = service.repository.get_account(clean_account_id)
            if not account:
                raise AccountNotFoundError(f"Account '{clean_account_id}' not found.")

        return AccountResponse(
            account_id=account.account_id,
            customer_id=account.customer_id,
            balance=account.balance,
            currency=account.currency,
            status=account.status,
            account_type=account.account_type,
        )

    except UnauthorizedAccessError as exc:
        logger.warning("Unauthorized account access attempt: %s", str(exc))
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access Forbidden: Customer is not authorized to view account '{clean_account_id}'."
        )

    except (AccountNotFoundError, CustomerNotFoundError) as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc)
        )

    except Exception as exc:
        # Mask internal error details
        logger.error("Internal error retrieving account: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while retrieving account information."
        )
