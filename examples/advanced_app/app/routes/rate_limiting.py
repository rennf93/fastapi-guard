from fastapi import APIRouter

from app.models import MessageResponse
from app.security import guard

router = APIRouter(prefix="/rate", tags=["Rate Limiting"])


@router.get("/custom-limit", response_model=MessageResponse)
@guard.rate_limit(requests=5, window=60)
async def custom_rate_limit() -> MessageResponse:
    return MessageResponse(
        message="Custom rate limit endpoint",
        details={"limit": "5 requests per 60 seconds"},
    )


@router.get("/strict-limit", response_model=MessageResponse)
@guard.rate_limit(requests=1, window=10)
async def strict_rate_limit() -> MessageResponse:
    return MessageResponse(
        message="Strict rate limit endpoint",
        details={"limit": "1 request per 10 seconds"},
    )


@router.get("/geo-rate-limit", response_model=MessageResponse)
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
