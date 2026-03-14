from typing import Any

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from app.models import MessageResponse
from app.security import guard

router = APIRouter(prefix="/content", tags=["Content Filtering"])


@router.get(
    "/no-bots",
    response_model=MessageResponse,
    status_code=200,
    summary="Bot Blocking",
    description=(
        "Blocks requests with user agent strings matching known bot patterns (bot,"
        "crawler, spider, scraper). Matches are case-insensitive substring checks."
    ),
    responses={403: {"description": "Bot user agent detected"}},
)
@guard.block_user_agents(["bot", "crawler", "spider", "scraper"])
async def block_bots() -> MessageResponse:
    return MessageResponse(message="Human users only - bots blocked")


@router.post(
    "/json-only",
    response_model=MessageResponse,
    status_code=200,
    summary="JSON Content Type Filter",
    description=(
        "Only accepts requests with Content-Type: application/json. Rejects requests"
        "with other content types."
    ),
    responses={415: {"description": "Unsupported content type"}},
)
@guard.content_type_filter(["application/json"])
async def json_content_only(data: dict[str, Any]) -> MessageResponse:
    return MessageResponse(
        message="JSON content received",
        details={"data": data},
    )


@router.post(
    "/size-limit",
    response_model=MessageResponse,
    status_code=200,
    summary="Request Size Limit",
    description=(
        "Rejects requests with a body larger than 100KB (102400 bytes). Prevents"
        "oversized payloads from consuming server resources."
    ),
    responses={413: {"description": "Request body exceeds 100KB limit"}},
)
@guard.max_request_size(1024 * 100)
async def limited_upload_size(data: dict[str, Any]) -> MessageResponse:
    return MessageResponse(
        message="Data received within size limit",
        details={"size_limit": "100KB"},
    )


@router.get(
    "/referrer-check",
    response_model=MessageResponse,
    status_code=200,
    summary="Referrer Validation",
    description=(
        "Only allows requests with a Referer header matching the specified origins."
        "Blocks direct access and requests from unauthorized referrers."
    ),
    responses={403: {"description": "Invalid or missing referrer"}},
)
@guard.require_referrer(["https://example.com", "https://app.example.com"])
async def check_referrer(request: Request) -> MessageResponse:
    referrer = request.headers.get("referer", "No referrer")
    return MessageResponse(
        message="Valid referrer",
        details={"referrer": referrer},
    )


async def custom_validator(request: Request) -> Response | None:
    user_agent = request.headers.get("user-agent", "").lower()
    if "suspicious-pattern" in user_agent:
        return JSONResponse(
            status_code=403,
            content={"detail": "Suspicious user agent detected"},
        )
    return None


@router.get(
    "/custom-validation",
    response_model=MessageResponse,
    status_code=200,
    summary="Custom Request Validation",
    description=(
        "Applies a custom validation function to the request. Demonstrates plugging in"
        "arbitrary validation logic that runs before the endpoint handler."
    ),
    responses={403: {"description": "Custom validation failed"}},
)
@guard.custom_validation(custom_validator)
async def custom_content_validation() -> MessageResponse:
    return MessageResponse(
        message="Custom validation passed",
        details={"validator": "custom_validator"},
    )
