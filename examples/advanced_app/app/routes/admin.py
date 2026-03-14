import logging
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Body

from app.models import MessageResponse, StatsResponse
from app.security import guard

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["Admin & Utilities"])


@router.post("/unban-ip", response_model=MessageResponse)
@guard.require_ip(whitelist=["127.0.0.1"])
async def unban_ip_address(
    ip: str = Body(..., description="IP address to unban"),
    background_tasks: BackgroundTasks = BackgroundTasks(),  # noqa: B008
) -> MessageResponse:
    background_tasks.add_task(logger.info, f"Unbanning IP: {ip}")
    return MessageResponse(
        message=f"IP {ip} has been unbanned",
        details={"action": "unban", "ip": ip},
    )


@router.get("/stats", response_model=StatsResponse)
@guard.require_ip(whitelist=["127.0.0.1"])
async def get_security_stats() -> StatsResponse:
    return StatsResponse(
        total_requests=1500,
        blocked_requests=75,
        banned_ips=["192.168.1.100", "10.0.0.50"],
        rate_limited_ips={"192.168.1.200": 5, "172.16.0.10": 3},
        suspicious_activities=[
            {
                "ip": "192.168.1.100",
                "reason": "SQL injection attempt",
                "timestamp": datetime.now(timezone.utc),
            },
            {
                "ip": "10.0.0.50",
                "reason": "Rapid requests",
                "timestamp": datetime.now(timezone.utc),
            },
        ],
        active_rules={
            "rate_limit": 30,
            "rate_window": 60,
            "auto_ban_threshold": 5,
            "blocked_countries": ["XX"],
            "blocked_clouds": ["AWS", "GCP", "Azure"],
        },
    )


@router.post("/clear-cache", response_model=MessageResponse)
@guard.require_ip(whitelist=["127.0.0.1"])
async def clear_security_cache() -> MessageResponse:
    return MessageResponse(
        message="Security caches cleared",
        details={"cleared": ["rate_limit_cache", "ip_ban_cache", "geo_cache"]},
    )


@router.put("/emergency-mode", response_model=MessageResponse)
@guard.require_ip(whitelist=["127.0.0.1"])
async def toggle_emergency_mode(
    enable: bool = Body(..., description="Enable or disable emergency mode"),
) -> MessageResponse:
    mode = "enabled" if enable else "disabled"
    return MessageResponse(
        message=f"Emergency mode {mode}",
        details={"emergency_mode": enable, "timestamp": datetime.now(timezone.utc)},
    )
