from fastapi import APIRouter, HTTPException

from app.models import MessageResponse
from app.security import guard
from guard.handlers.behavior_handler import BehaviorRule

router = APIRouter(prefix="/behavior", tags=["Behavioral Analysis"])


@router.get(
    "/usage-monitor",
    response_model=MessageResponse,
    status_code=200,
    summary="Usage Pattern Monitoring",
    description=(
        "Monitors request frequency per client. Logs a warning when a client exceeds 10"
        "calls within a 5-minute window. Does not block requests."
    ),
    responses={429: {"description": "Usage limit exceeded (if action is block)"}},
)
@guard.usage_monitor(max_calls=10, window=300, action="log")
async def monitor_usage_patterns() -> MessageResponse:
    return MessageResponse(
        message="Usage monitoring active",
        details={"monitoring": "10 calls per 5 minutes"},
    )


@router.get(
    "/return-monitor/{status_code}",
    response_model=MessageResponse,
    status_code=200,
    summary="Return Pattern Monitoring",
    description=(
        "Monitors response status code patterns. Automatically bans clients that"
        " trigger"
        "3 or more 404 responses within 60 seconds, indicating potential path"
        "enumeration."
    ),
    responses={
        403: {"description": "Client banned due to suspicious 404 pattern"},
        404: {"description": "Resource not found"},
    },
)
@guard.return_monitor(pattern="404", max_occurrences=3, window=60, action="ban")
async def monitor_return_patterns(status_code: int) -> MessageResponse:
    if status_code == 404:
        raise HTTPException(status_code=404, detail="Not found")
    return MessageResponse(message=f"Status code: {status_code}")


@router.get(
    "/suspicious-frequency",
    response_model=MessageResponse,
    status_code=200,
    summary="Suspicious Frequency Detection",
    description=(
        "Detects clients sending requests faster than 1 every 2 seconds (0.5 Hz) within"
        "a 10-second window. Throttles suspicious clients rather than banning them."
    ),
    responses={429: {"description": "Throttled due to suspicious request frequency"}},
)
@guard.suspicious_frequency(max_frequency=0.5, window=10, action="throttle")
async def detect_suspicious_frequency() -> MessageResponse:
    return MessageResponse(
        message="Frequency monitoring active",
        details={"max_frequency": "1 request per 2 seconds"},
    )


@router.post(
    "/behavior-rules",
    response_model=MessageResponse,
    status_code=200,
    summary="Complex Behavior Analysis",
    description=(
        "Applies multiple behavioral rules simultaneously: frequency-based throttling"
        "(10 requests/min) and return pattern monitoring (5 or more 404s/min triggers a"
        "ban)."
    ),
    responses={
        403: {"description": "Banned due to suspicious return patterns"},
        429: {"description": "Throttled due to high request frequency"},
    },
)
@guard.behavior_analysis(
    [
        BehaviorRule(rule_type="frequency", threshold=10, window=60, action="throttle"),
        BehaviorRule(
            rule_type="return_pattern",
            pattern="404",
            threshold=5,
            window=60,
            action="ban",
        ),
    ]
)
async def complex_behavior_analysis() -> MessageResponse:
    return MessageResponse(
        message="Complex behavior analysis active",
        details={"rules": ["frequency", "return_pattern"]},
    )
