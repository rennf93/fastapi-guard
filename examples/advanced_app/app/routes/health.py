from datetime import datetime, timezone

from fastapi import APIRouter

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check() -> dict[str, str | datetime]:
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc)}


@router.get("/ready")
async def readiness_check() -> dict[str, str | datetime]:
    return {"status": "ready", "timestamp": datetime.now(timezone.utc)}
