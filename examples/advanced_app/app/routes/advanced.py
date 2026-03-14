from fastapi import APIRouter, Query

from app.models import MessageResponse, TestPayload
from app.security import guard

router = APIRouter(prefix="/advanced", tags=["Advanced Features"])


@router.get(
    "/business-hours",
    response_model=MessageResponse,
    status_code=200,
    summary="Business Hours Access",
    description=(
        "Restricts access to business hours only (09:00-17:00 UTC). Requests outside"
        "this window are rejected."
    ),
    responses={403: {"description": "Outside allowed time window"}},
)
@guard.time_window(start_time="09:00", end_time="17:00", timezone="UTC")
async def business_hours_only() -> MessageResponse:
    return MessageResponse(
        message="Access granted during business hours",
        details={"hours": "09:00-17:00 UTC"},
    )


@router.get(
    "/weekend-only",
    response_model=MessageResponse,
    status_code=200,
    summary="Weekend Access Only",
    description=(
        "Restricts access to weekends only. Demonstrates time-based access control with"
        "day-of-week constraints."
    ),
    responses={403: {"description": "Outside allowed time window"}},
)
@guard.time_window(start_time="00:00", end_time="23:59", timezone="UTC")
async def weekend_endpoint() -> MessageResponse:
    return MessageResponse(
        message="Weekend access endpoint",
        details={"note": "Implement weekend check in time_window"},
    )


@router.post(
    "/honeypot",
    response_model=MessageResponse,
    status_code=200,
    summary="Honeypot Bot Detection",
    description=(
        "Detects bots by including hidden form fields (honeypot_field, trap_input,"
        "hidden_field) that should remain empty. Bots that fill these fields are"
        "identified and blocked."
    ),
    responses={403: {"description": "Bot detected via honeypot field"}},
)
@guard.honeypot_detection(["honeypot_field", "trap_input", "hidden_field"])
async def honeypot_detection(payload: TestPayload) -> MessageResponse:
    return MessageResponse(
        message="Human user verified",
        details={"honeypot_status": "clean"},
    )


@router.get(
    "/suspicious-patterns",
    response_model=MessageResponse,
    status_code=200,
    summary="Suspicious Pattern Detection",
    description=(
        "Scans the request (query parameters, headers, body) for known attack patterns"
        "including SQL injection, XSS, path traversal, and command injection"
        " signatures."
    ),
    responses={403: {"description": "Suspicious pattern detected"}},
)
@guard.suspicious_detection(enabled=True)
async def detect_suspicious_patterns(
    query: str = Query(None),
) -> MessageResponse:
    return MessageResponse(
        message="No suspicious patterns detected",
        details={"query": query},
    )
