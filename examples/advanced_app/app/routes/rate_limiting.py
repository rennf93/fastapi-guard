from fastapi import APIRouter

from app.models import MessageResponse
from app.security import guard

router = APIRouter(prefix="/rate", tags=["Rate Limiting"])


@router.get(
    "/custom-limit",
    response_model=MessageResponse,
    status_code=200,
    summary="Custom Rate Limit",
    description=(
        "Applies a per-route rate limit of 5 requests per 60 seconds. Uses atomic Lua"
        "scripts with Redis sorted sets for distributed consistency, with in-memory"
        "fallback."
    ),
    responses={429: {"description": "Rate limit exceeded"}},
)
@guard.rate_limit(requests=5, window=60)
async def custom_rate_limit() -> MessageResponse:
    return MessageResponse(
        message="Custom rate limit endpoint",
        details={"limit": "5 requests per 60 seconds"},
    )


@router.get(
    "/strict-limit",
    response_model=MessageResponse,
    status_code=200,
    summary="Strict Rate Limit",
    description=(
        "Applies a strict per-route rate limit of 1 request per 10 seconds."
        " Demonstrates"
        "aggressive throttling for sensitive endpoints."
    ),
    responses={429: {"description": "Rate limit exceeded"}},
)
@guard.rate_limit(requests=1, window=10)
async def strict_rate_limit() -> MessageResponse:
    return MessageResponse(
        message="Strict rate limit endpoint",
        details={"limit": "1 request per 10 seconds"},
    )


@router.get(
    "/geo-rate-limit",
    response_model=MessageResponse,
    status_code=200,
    summary="Geographic Rate Limiting",
    description=(
        "Applies different rate limits based on the client's country of origin. US gets"
        "100 req/min, CN gets 10, RU gets 20, and all other countries get 50. Country"
        " is"
        "resolved via local MaxMind database."
    ),
    responses={429: {"description": "Rate limit exceeded"}},
)
@guard.geo_rate_limit(
    {
        "US": (100, 60),
        "CN": (10, 60),
        "RU": (20, 60),
        "*": (50, 60),
    }
)
async def geographic_rate_limiting() -> MessageResponse:
    return MessageResponse(
        message="Geographic rate limiting applied",
        details={"description": "Rate limits vary by country"},
    )
