from typing import Annotated

from fastapi import APIRouter, Header, Request

from app.models import AuthResponse, MessageResponse
from app.security import guard

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.get(
    "/https-only",
    response_model=MessageResponse,
    status_code=200,
    summary="HTTPS Enforcement",
    description=(
        "Requires HTTPS connection. HTTP requests are redirected to HTTPS with a 301"
        "status. Supports X-Forwarded-Proto detection behind trusted proxies."
    ),
    responses={301: {"description": "Redirected to HTTPS"}},
)
@guard.require_https()
async def https_required_endpoint(request: Request) -> MessageResponse:
    return MessageResponse(
        message="HTTPS connection verified",
        details={"protocol": request.url.scheme},
    )


@router.get(
    "/bearer-auth",
    response_model=AuthResponse,
    status_code=200,
    summary="Bearer Token Authentication",
    description=(
        "Requires a valid Bearer token in the Authorization header. Rejects requests"
        "without the header or with an invalid format."
    ),
    responses={401: {"description": "Missing or invalid Bearer token"}},
)
@guard.require_auth(type="bearer")
async def bearer_authentication(
    authorization: Annotated[str | None, Header()] = None,
) -> AuthResponse:
    return AuthResponse(
        authenticated=True,
        user="example_user",
        method="bearer",
        permissions=["read", "write"],
    )


@router.get(
    "/api-key",
    response_model=AuthResponse,
    status_code=200,
    summary="API Key Authentication",
    description=(
        "Requires a valid API key in the X-API-Key header. Rejects requests without the"
        "header."
    ),
    responses={401: {"description": "Missing or invalid API key"}},
)
@guard.api_key_auth(header_name="X-API-Key")
async def api_key_authentication(
    x_api_key: Annotated[str | None, Header()] = None,
) -> AuthResponse:
    return AuthResponse(
        authenticated=True,
        user="api_user",
        method="api_key",
        permissions=["read"],
    )


@router.get(
    "/custom-headers",
    response_model=MessageResponse,
    status_code=200,
    summary="Required Custom Headers",
    description=(
        "Enforces the presence of specific custom headers with required values."
        " Requests"
        "missing any required header are rejected."
    ),
    responses={403: {"description": "Missing required headers"}},
)
@guard.require_headers(
    {"X-Custom-Header": "required-value", "X-Client-ID": "required-value"}
)
async def require_custom_headers(request: Request) -> MessageResponse:
    return MessageResponse(
        message="Required headers verified",
        details={"headers": dict(request.headers)},
    )
