from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class MessageResponse(BaseModel):
    message: str
    details: dict[str, Any] | None = None


class IPInfoResponse(BaseModel):
    ip: str
    country: str | None = None
    city: str | None = None
    region: str | None = None
    is_vpn: bool | None = None
    is_cloud: bool | None = None
    cloud_provider: str | None = None


class StatsResponse(BaseModel):
    total_requests: int
    blocked_requests: int
    banned_ips: list[str]
    rate_limited_ips: dict[str, int]
    suspicious_activities: list[dict[str, Any]]
    active_rules: dict[str, Any]


class ErrorResponse(BaseModel):
    detail: str
    error_code: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AuthResponse(BaseModel):
    authenticated: bool
    user: str | None = None
    method: str
    permissions: list[str] = Field(default_factory=list)


class TestPayload(BaseModel):
    input: str | None = Field(None, description="Test input for XSS detection")
    query: str | None = Field(None, description="Test query for SQL injection")
    path: str | None = Field(None, description="Test path for traversal attacks")
    cmd: str | None = Field(None, description="Test command for injection")
    honeypot_field: str | None = Field(
        None, description="Hidden field for bot detection"
    )
