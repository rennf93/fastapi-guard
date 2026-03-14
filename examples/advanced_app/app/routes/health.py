from datetime import datetime, timezone

from fastapi import APIRouter

from app.models import HealthResponse, ReadinessResponse

router = APIRouter(tags=["Health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=200,
    summary="Health Check",
    description=(
        "Returns the current health status and timestamp. Used by load balancers and"
        "orchestrators to verify the service is running."
    ),
)
async def health_check() -> HealthResponse:
    return HealthResponse(status="healthy", timestamp=datetime.now(timezone.utc))


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    status_code=200,
    summary="Readiness Check",
    description=(
        "Returns readiness status and timestamp. Used by orchestrators to determine if"
        "the service is ready to accept traffic."
    ),
)
async def readiness_check() -> ReadinessResponse:
    return ReadinessResponse(status="ready", timestamp=datetime.now(timezone.utc))
