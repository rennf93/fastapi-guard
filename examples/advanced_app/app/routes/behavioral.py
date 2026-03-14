from fastapi import APIRouter, HTTPException

from app.models import MessageResponse
from app.security import guard
from guard.handlers.behavior_handler import BehaviorRule

router = APIRouter(prefix="/behavior", tags=["Behavioral Analysis"])


@router.get("/usage-monitor", response_model=MessageResponse)
@guard.usage_monitor(max_calls=10, window=300, action="log")
async def monitor_usage_patterns() -> MessageResponse:
    return MessageResponse(
        message="Usage monitoring active",
        details={"monitoring": "10 calls per 5 minutes"},
    )


@router.get("/return-monitor/{status_code}")
@guard.return_monitor(pattern="404", max_occurrences=3, window=60, action="ban")
async def monitor_return_patterns(status_code: int) -> MessageResponse:
    if status_code == 404:
        raise HTTPException(status_code=404, detail="Not found")
    return MessageResponse(message=f"Status code: {status_code}")


@router.get("/suspicious-frequency", response_model=MessageResponse)
@guard.suspicious_frequency(max_frequency=0.5, window=10, action="throttle")
async def detect_suspicious_frequency() -> MessageResponse:
    return MessageResponse(
        message="Frequency monitoring active",
        details={"max_frequency": "1 request per 2 seconds"},
    )


@router.post("/behavior-rules", response_model=MessageResponse)
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
