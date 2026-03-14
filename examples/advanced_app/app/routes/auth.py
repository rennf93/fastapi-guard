from typing import Annotated

from fastapi import APIRouter, Header, Request

from app.models import AuthResponse, MessageResponse
from app.security import guard

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.get("/https-only", response_model=MessageResponse)
@guard.require_https()
async def https_required_endpoint(request: Request) -> MessageResponse:
    return MessageResponse(
        message="HTTPS connection verified",
        details={"protocol": request.url.scheme},
    )


@router.get("/bearer-auth", response_model=AuthResponse)
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


@router.get("/api-key", response_model=AuthResponse)
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


@router.get("/custom-headers", response_model=MessageResponse)
@guard.require_headers(
    {"X-Custom-Header": "required-value", "X-Client-ID": "required-value"}
)
async def require_custom_headers(request: Request) -> MessageResponse:
    return MessageResponse(
        message="Required headers verified",
        details={"headers": dict(request.headers)},
    )
