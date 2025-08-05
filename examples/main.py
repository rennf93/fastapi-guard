"""
FastAPI Guard Comprehensive Example
===================================

This example demonstrates ALL features of the FastAPI Guard security middleware.

Features demonstrated:
- IP whitelisting/blacklisting with CIDR support
- Country-based filtering (blocking and allowing)
- Cloud provider IP blocking
- Rate limiting (global and per-endpoint)
- Automatic IP banning
- Penetration attempt detection
- User agent filtering
- Content type filtering
- Request size limiting
- Time-based access control
- Behavioral analysis and monitoring
- Custom authentication schemes
- Honeypot detection
- Redis integration for distributed environments
- Agent integration for telemetry
- Dynamic rule management
- Emergency mode
- WebSocket protection
- And much more!

Run with: uvicorn main:app --reload
"""

import logging
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Annotated, Any

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Body,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from guard import SecurityConfig, SecurityMiddleware
from guard.decorators import SecurityDecorator
from guard.handlers.behavior_handler import BehaviorRule
from guard.handlers.ipinfo_handler import IPInfoManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# ==================== Response Models ====================


class MessageResponse(BaseModel):
    message: str
    details: dict[str, Any] | None = None

    class Config:
        json_schema_extra = {
            "example": {
                "message": "Success",
                "details": {"info": "Additional information"},
            }
        }


class IPInfoResponse(BaseModel):
    ip: str
    country: str | None = None
    city: str | None = None
    region: str | None = None
    is_vpn: bool | None = None
    is_cloud: bool | None = None
    cloud_provider: str | None = None

    class Config:
        json_schema_extra = {
            "example": {
                "ip": "8.8.8.8",
                "country": "US",
                "city": "Mountain View",
                "region": "California",
                "is_vpn": False,
                "is_cloud": True,
                "cloud_provider": "Google",
            }
        }


class StatsResponse(BaseModel):
    total_requests: int
    blocked_requests: int
    banned_ips: list[str]
    rate_limited_ips: dict[str, int]
    suspicious_activities: list[dict[str, Any]]
    active_rules: dict[str, Any]

    class Config:
        json_schema_extra = {
            "example": {
                "total_requests": 1000,
                "blocked_requests": 50,
                "banned_ips": ["192.168.1.100", "10.0.0.50"],
                "rate_limited_ips": {"192.168.1.200": 5},
                "suspicious_activities": [
                    {"ip": "192.168.1.100", "reason": "SQL injection attempt"}
                ],
                "active_rules": {"rate_limit": 10, "auto_ban_threshold": 5},
            }
        }


class ErrorResponse(BaseModel):
    detail: str
    error_code: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        json_schema_extra = {
            "example": {
                "detail": "Access denied",
                "error_code": "ACCESS_DENIED",
                "timestamp": "2024-01-20T10:30:00Z",
            }
        }


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


# ==================== Custom Hooks ====================


async def custom_request_check(request: Request) -> Response | None:
    """Custom request validation hook."""
    # Example: Block requests with specific query parameters
    if "debug" in request.query_params and request.query_params["debug"] == "true":
        logger.warning(
            f"Blocked debug request from {request.client.host if request.client else 'unknown'}"  # noqa: E501
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": "Debug mode not allowed"},
        )
    return None


async def custom_response_modifier(response: Response) -> Response:
    """Custom response modification hook."""
    # Add security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ==================== Security Configuration ====================

security_config = SecurityConfig(
    # IP Configuration
    whitelist=["127.0.0.1", "::1", "10.0.0.0/8"],  # Localhost and private network
    blacklist=["192.168.100.0/24"],  # Example blacklisted subnet
    # Proxy Configuration
    trusted_proxies=["127.0.0.1", "10.0.0.0/8"],
    trusted_proxy_depth=2,
    trust_x_forwarded_proto=True,
    # Geographical Filtering (requires ipinfo_token)
    geo_ip_handler=IPInfoManager("your_token_here"),  # Replace with actual token
    blocked_countries=["XX"],  # Example: block country code XX
    whitelist_countries=[],  # Allow all countries by default
    # Cloud Provider Blocking
    block_cloud_providers={"AWS", "GCP", "Azure"},
    # User Agent Filtering
    blocked_user_agents=["badbot", "evil-crawler", "sqlmap"],
    # Rate Limiting
    enable_rate_limiting=True,
    rate_limit=30,  # 30 requests
    rate_limit_window=60,  # per 60 seconds
    # Auto-banning
    enable_ip_banning=True,
    auto_ban_threshold=5,
    auto_ban_duration=300,  # 5 minutes
    # Penetration Detection
    enable_penetration_detection=True,
    # Redis Configuration
    enable_redis=True,
    redis_url="redis://localhost:6379",
    redis_prefix="fastapi_guard:",
    # HTTPS Enforcement
    enforce_https=False,  # Set to True in production
    # Custom Hooks
    custom_request_check=custom_request_check,
    custom_response_modifier=custom_response_modifier,
    # CORS Configuration
    enable_cors=True,
    cors_allow_origins=["http://localhost:3000", "https://example.com"],
    cors_allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    cors_allow_headers=["*"],
    cors_allow_credentials=True,
    cors_expose_headers=["X-Total-Count"],
    cors_max_age=3600,
    # Logging
    log_request_level="INFO",
    log_suspicious_level="WARNING",
    custom_log_file="security_events.log",
    # Excluded Paths
    exclude_paths=[
        "/docs",
        "/redoc",
        "/openapi.json",
        "/favicon.ico",
        "/static",
        "/health",
    ],
    # Agent Configuration (optional)
    enable_agent=False,  # Set to True to enable telemetry
    agent_api_key="your_agent_api_key",
    agent_project_id="example_project",
    # Advanced Configuration
    passive_mode=False,  # Set to True for log-only mode
)

# Initialize FastAPI app
app = FastAPI(
    title="FastAPI Guard Comprehensive Example",
    description=__doc__,
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Add security middleware
app.add_middleware(SecurityMiddleware, config=security_config)

# Initialize security decorator
guard_decorator = SecurityDecorator(security_config)


# ==================== Basic Features Router ====================

basic_router = APIRouter(prefix="/basic", tags=["Basic Features"])


@basic_router.get("/", response_model=MessageResponse)
async def basic_root() -> MessageResponse:
    """Basic endpoint to test connection and rate limiting."""
    return MessageResponse(message="Basic features endpoint")


@basic_router.get("/ip", response_model=IPInfoResponse)
async def get_ip_info(request: Request) -> IPInfoResponse:
    """Get detailed information about the client's IP address."""
    client_ip = "unknown"
    if request.client:
        try:
            client_ip = str(ip_address(request.client.host))
        except ValueError:
            client_ip = request.client.host

    # In a real scenario, you would use the geo_ip_handler to get this info
    return IPInfoResponse(
        ip=client_ip,
        country="US",
        city="Example City",
        region="Example Region",
        is_vpn=False,
        is_cloud=False,
    )


@basic_router.get("/health")
async def health_check() -> dict[str, Any]:
    """Health check endpoint (excluded from security checks)."""
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc)}


@basic_router.post("/echo", response_model=MessageResponse)
async def echo_request(
    request: Request,
    data: dict[str, Any] = Body(..., description="Request data"),  # noqa: B008
) -> MessageResponse:
    """Echo back the request data with headers info."""
    return MessageResponse(
        message="Echo response",
        details={
            "data": data,
            "headers": dict(request.headers),
            "method": request.method,
            "url": str(request.url),
        },
    )


# ==================== Access Control Router ====================

access_router = APIRouter(prefix="/access", tags=["Access Control"])


@access_router.get("/ip-whitelist", response_model=MessageResponse)
@guard_decorator.require_ip(whitelist=["127.0.0.1", "10.0.0.0/8"])
async def ip_whitelist_only() -> MessageResponse:
    """Only accessible from whitelisted IPs."""
    return MessageResponse(message="Access granted from whitelisted IP")


@access_router.get("/ip-blacklist", response_model=MessageResponse)
@guard_decorator.require_ip(blacklist=["192.168.1.0/24", "172.16.0.0/12"])
async def ip_blacklist_demo() -> MessageResponse:
    """Blocked for specific IP ranges."""
    return MessageResponse(message="Access granted - you're not blacklisted")


@access_router.get("/country-block", response_model=MessageResponse)
@guard_decorator.block_countries(["CN", "RU", "KP"])
async def block_specific_countries() -> MessageResponse:
    """Block access from specific countries."""
    return MessageResponse(message="Access granted - your country is not blocked")


@access_router.get("/country-allow", response_model=MessageResponse)
@guard_decorator.allow_countries(["US", "CA", "GB", "AU"])
async def allow_specific_countries() -> MessageResponse:
    """Only allow access from specific countries."""
    return MessageResponse(message="Access granted from allowed country")


@access_router.get("/no-cloud", response_model=MessageResponse)
@guard_decorator.block_clouds()  # Block all cloud providers
async def block_all_clouds() -> MessageResponse:
    """Block access from all cloud provider IPs."""
    return MessageResponse(message="Access granted - not from cloud provider")


@access_router.get("/no-aws", response_model=MessageResponse)
@guard_decorator.block_clouds(["AWS"])
async def block_aws_only() -> MessageResponse:
    """Block access only from AWS IPs."""
    return MessageResponse(message="Access granted - not from AWS")


@access_router.get("/bypass-demo", response_model=MessageResponse)
@guard_decorator.bypass(["rate_limit", "geo_check"])
async def bypass_specific_checks() -> MessageResponse:
    """Bypass rate limiting and geo checks for this endpoint."""
    return MessageResponse(
        message="This endpoint bypasses rate limiting and geo checks",
        details={"bypassed_checks": ["rate_limit", "geo_check"]},
    )


# ==================== Authentication Router ====================

auth_router = APIRouter(prefix="/auth", tags=["Authentication"])


@auth_router.get("/https-only", response_model=MessageResponse)
@guard_decorator.require_https()
async def https_required_endpoint(request: Request) -> MessageResponse:
    """This endpoint requires HTTPS connection."""
    return MessageResponse(
        message="HTTPS connection verified",
        details={"protocol": request.url.scheme},
    )


@auth_router.get("/bearer-auth", response_model=AuthResponse)
@guard_decorator.require_auth(type="bearer")
async def bearer_authentication(
    authorization: Annotated[str | None, Header()] = None,
) -> AuthResponse:
    """Requires Bearer token authentication."""
    return AuthResponse(
        authenticated=True,
        user="example_user",
        method="bearer",
        permissions=["read", "write"],
    )


@auth_router.get("/api-key", response_model=AuthResponse)
@guard_decorator.api_key_auth(header_name="X-API-Key")
async def api_key_authentication(
    x_api_key: Annotated[str | None, Header()] = None,
) -> AuthResponse:
    """Requires API key in X-API-Key header."""
    return AuthResponse(
        authenticated=True,
        user="api_user",
        method="api_key",
        permissions=["read"],
    )


@auth_router.get("/custom-headers", response_model=MessageResponse)
@guard_decorator.require_headers(
    {"X-Custom-Header": "required-value", "X-Client-ID": "required-value"}
)
async def require_custom_headers(
    request: Request,
) -> MessageResponse:
    """Requires specific headers to be present."""
    return MessageResponse(
        message="Required headers verified",
        details={"headers": dict(request.headers)},
    )


# ==================== Rate Limiting Router ====================

rate_router = APIRouter(prefix="/rate", tags=["Rate Limiting"])


@rate_router.get("/custom-limit", response_model=MessageResponse)
@guard_decorator.rate_limit(requests=5, window=60)
async def custom_rate_limit() -> MessageResponse:
    """Custom rate limit: 5 requests per minute."""
    return MessageResponse(
        message="Custom rate limit endpoint",
        details={"limit": "5 requests per 60 seconds"},
    )


@rate_router.get("/strict-limit", response_model=MessageResponse)
@guard_decorator.rate_limit(requests=1, window=10)
async def strict_rate_limit() -> MessageResponse:
    """Very strict rate limit: 1 request per 10 seconds."""
    return MessageResponse(
        message="Strict rate limit endpoint",
        details={"limit": "1 request per 10 seconds"},
    )


@rate_router.get("/geo-rate-limit", response_model=MessageResponse)
@guard_decorator.geo_rate_limit(
    {
        "US": (100, 60),  # 100 requests per minute for US
        "CN": (10, 60),  # 10 requests per minute for China
        "RU": (20, 60),  # 20 requests per minute for Russia
        "*": (50, 60),  # 50 requests per minute for others
    }
)
async def geographic_rate_limiting() -> MessageResponse:
    """Different rate limits based on country."""
    return MessageResponse(
        message="Geographic rate limiting applied",
        details={"description": "Rate limits vary by country"},
    )


# ==================== Behavioral Analysis Router ====================

behavior_router = APIRouter(prefix="/behavior", tags=["Behavioral Analysis"])


@behavior_router.get("/usage-monitor", response_model=MessageResponse)
@guard_decorator.usage_monitor(max_calls=10, window=300, action="log")
async def monitor_usage_patterns() -> MessageResponse:
    """Monitor endpoint usage: log if more than 10 calls in 5 minutes."""
    return MessageResponse(
        message="Usage monitoring active",
        details={"monitoring": "10 calls per 5 minutes"},
    )


@behavior_router.get("/return-monitor/{status_code}")
@guard_decorator.return_monitor(
    pattern="404",
    max_occurrences=3,
    window=60,
    action="ban"
)
async def monitor_return_patterns(status_code: int) -> MessageResponse:
    """Ban IP if it receives 404 more than 3 times in 60 seconds."""
    if status_code == 404:
        raise HTTPException(status_code=404, detail="Not found")
    return MessageResponse(message=f"Status code: {status_code}")


@behavior_router.get("/suspicious-frequency", response_model=MessageResponse)
@guard_decorator.suspicious_frequency(max_frequency=0.5, window=10, action="throttle")
async def detect_suspicious_frequency() -> MessageResponse:
    """Detect suspicious request frequency: max 1 request per 2 seconds."""
    return MessageResponse(
        message="Frequency monitoring active",
        details={"max_frequency": "1 request per 2 seconds"},
    )


@behavior_router.post("/behavior-rules", response_model=MessageResponse)
@guard_decorator.behavior_analysis(
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
    """Complex behavioral analysis with multiple rules."""
    return MessageResponse(
        message="Complex behavior analysis active",
        details={"rules": ["frequency", "return_pattern"]},
    )


# ==================== Content Filtering Router ====================

content_router = APIRouter(prefix="/content", tags=["Content Filtering"])


@content_router.get("/no-bots", response_model=MessageResponse)
@guard_decorator.block_user_agents(["bot", "crawler", "spider", "scraper"])
async def block_bots() -> MessageResponse:
    """Block common bot user agents."""
    return MessageResponse(message="Human users only - bots blocked")


@content_router.post("/json-only", response_model=MessageResponse)
@guard_decorator.content_type_filter(["application/json"])
async def json_content_only(data: dict[str, Any]) -> MessageResponse:
    """Only accept JSON content type."""
    return MessageResponse(
        message="JSON content received",
        details={"data": data},
    )


@content_router.post("/size-limit", response_model=MessageResponse)
@guard_decorator.max_request_size(1024 * 100)  # 100KB limit
async def limited_upload_size(data: dict[str, Any]) -> MessageResponse:
    """Limit request body size to 100KB."""
    return MessageResponse(
        message="Data received within size limit",
        details={"size_limit": "100KB"},
    )


@content_router.get("/referrer-check", response_model=MessageResponse)
@guard_decorator.require_referrer(["https://example.com", "https://app.example.com"])
async def check_referrer(request: Request) -> MessageResponse:
    """Require requests to come from specific referrer domains."""
    referrer = request.headers.get("referer", "No referrer")
    return MessageResponse(
        message="Valid referrer",
        details={"referrer": referrer},
    )


async def custom_validator(request: Request) -> Response | None:
    """Custom validation logic."""
    # Example: Check for specific user agent pattern
    user_agent = request.headers.get("user-agent", "").lower()
    if "suspicious-pattern" in user_agent:
        return JSONResponse(
            status_code=403,
            content={"detail": "Suspicious user agent detected"},
        )
    return None


@content_router.get("/custom-validation", response_model=MessageResponse)
@guard_decorator.custom_validation(custom_validator)
async def custom_content_validation() -> MessageResponse:
    """Custom validation logic for requests."""
    return MessageResponse(
        message="Custom validation passed",
        details={"validator": "custom_validator"},
    )


# ==================== Advanced Features Router ====================

advanced_router = APIRouter(prefix="/advanced", tags=["Advanced Features"])


@advanced_router.get("/business-hours", response_model=MessageResponse)
@guard_decorator.time_window(start_time="09:00", end_time="17:00", timezone="UTC")
async def business_hours_only() -> MessageResponse:
    """Only accessible during business hours (9 AM - 5 PM UTC)."""
    return MessageResponse(
        message="Access granted during business hours",
        details={"hours": "09:00-17:00 UTC"},
    )


@advanced_router.get("/weekend-only", response_model=MessageResponse)
@guard_decorator.time_window(start_time="00:00", end_time="23:59", timezone="UTC")
async def weekend_endpoint() -> MessageResponse:
    """This would need custom logic to check for weekends."""
    return MessageResponse(
        message="Weekend access endpoint",
        details={"note": "Implement weekend check in time_window"},
    )


@advanced_router.post("/honeypot", response_model=MessageResponse)
@guard_decorator.honeypot_detection(["honeypot_field", "trap_input", "hidden_field"])
async def honeypot_detection(payload: TestPayload) -> MessageResponse:
    """Detect bots using honeypot fields."""
    return MessageResponse(
        message="Human user verified",
        details={"honeypot_status": "clean"},
    )


@advanced_router.get("/suspicious-patterns", response_model=MessageResponse)
@guard_decorator.suspicious_detection(enabled=True)
async def detect_suspicious_patterns(
    query: str = Query(None, description="Test query parameter"),
) -> MessageResponse:
    """Enable enhanced suspicious pattern detection."""
    return MessageResponse(
        message="No suspicious patterns detected",
        details={"query": query},
    )


# ==================== Admin/Utility Router ====================

admin_router = APIRouter(prefix="/admin", tags=["Admin & Utilities"])


@admin_router.post("/unban-ip", response_model=MessageResponse)
@guard_decorator.require_ip(whitelist=["127.0.0.1"])  # Admin only from localhost
async def unban_ip_address(
    ip: str = Body(..., description="IP address to unban"),
    background_tasks: BackgroundTasks = BackgroundTasks(),  # noqa: B008
) -> MessageResponse:
    """Unban a specific IP address (admin only)."""
    # In real implementation, you would access the IPBanHandler
    background_tasks.add_task(logger.info, f"Unbanning IP: {ip}")
    return MessageResponse(
        message=f"IP {ip} has been unbanned",
        details={"action": "unban", "ip": ip},
    )


@admin_router.get("/stats", response_model=StatsResponse)
@guard_decorator.require_ip(whitelist=["127.0.0.1"])
async def get_security_stats() -> StatsResponse:
    """Get security statistics (admin only)."""
    # In real implementation, you would gather actual stats
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


@admin_router.post("/clear-cache", response_model=MessageResponse)
@guard_decorator.require_ip(whitelist=["127.0.0.1"])
async def clear_security_cache() -> MessageResponse:
    """Clear security-related caches (admin only)."""
    return MessageResponse(
        message="Security caches cleared",
        details={"cleared": ["rate_limit_cache", "ip_ban_cache", "geo_cache"]},
    )


@admin_router.put("/emergency-mode", response_model=MessageResponse)
@guard_decorator.require_ip(whitelist=["127.0.0.1"])
async def toggle_emergency_mode(
    enable: bool = Body(..., description="Enable or disable emergency mode"),
) -> MessageResponse:
    """Toggle emergency mode (admin only)."""
    # In real implementation, you would update the config
    mode = "enabled" if enable else "disabled"
    return MessageResponse(
        message=f"Emergency mode {mode}",
        details={"emergency_mode": enable, "timestamp": datetime.now(timezone.utc)},
    )


# ==================== Testing/Attack Simulation Router ====================

test_router = APIRouter(prefix="/test", tags=["Security Testing"])


@test_router.post("/xss-test", response_model=MessageResponse)
async def test_xss_detection(
    payload: str = Body(..., description="XSS test payload"),
) -> MessageResponse:
    """Test XSS detection capabilities."""
    # The middleware should catch malicious payloads
    return MessageResponse(
        message="XSS test payload processed",
        details={"payload": payload, "detected": False},
    )


@test_router.post("/sql-injection", response_model=MessageResponse)
async def test_sql_injection(
    query: str = Query(..., description="SQL injection test"),
) -> MessageResponse:
    """Test SQL injection detection."""
    return MessageResponse(
        message="SQL injection test processed",
        details={"query": query, "detected": False},
    )


@test_router.get("/path-traversal/{file_path:path}")
async def test_path_traversal(file_path: str) -> MessageResponse:
    """Test path traversal detection."""
    return MessageResponse(
        message="Path traversal test",
        details={"path": file_path, "detected": False},
    )


@test_router.post("/command-injection", response_model=MessageResponse)
async def test_command_injection(
    command: str = Body(..., description="Command injection test"),
) -> MessageResponse:
    """Test command injection detection."""
    return MessageResponse(
        message="Command injection test processed",
        details={"command": command, "detected": False},
    )


@test_router.post("/mixed-attack", response_model=MessageResponse)
async def test_mixed_attack(payload: TestPayload) -> MessageResponse:
    """Test multiple attack vectors simultaneously."""
    return MessageResponse(
        message="Mixed attack test processed",
        details={
            "xss_test": payload.input,
            "sql_test": payload.query,
            "path_test": payload.path,
            "cmd_test": payload.cmd,
            "honeypot": payload.honeypot_field,
        },
    )


# ==================== WebSocket Endpoint ====================


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """WebSocket endpoint with security protection."""
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            # Echo the message back
            await websocket.send_text(f"Echo: {data}")

            # Simulate some processing
            if data == "status":
                await websocket.send_json(
                    {
                        "type": "status",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "security": "active",
                    }
                )
    except WebSocketDisconnect:
        logger.info("WebSocket disconnected")


# ==================== Root Endpoint ====================


@app.get("/", response_model=MessageResponse)
async def root() -> MessageResponse:
    """Welcome endpoint with API information."""
    return MessageResponse(
        message="FastAPI Guard Comprehensive Example API",
        details={
            "version": "2.0.0",
            "features": [
                "IP filtering",
                "Country blocking",
                "Cloud provider blocking",
                "Rate limiting",
                "Behavioral analysis",
                "Content filtering",
                "Authentication",
                "Advanced security features",
            ],
            "documentation": "/docs",
            "routes": {
                "/basic": "Basic security features",
                "/access": "Access control demonstrations",
                "/auth": "Authentication examples",
                "/rate": "Rate limiting examples",
                "/behavior": "Behavioral analysis",
                "/content": "Content filtering",
                "/advanced": "Advanced features",
                "/admin": "Admin utilities",
                "/test": "Security testing",
                "/ws": "WebSocket endpoint",
            },
        },
    )


# ==================== Error Handlers ====================


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Custom HTTP exception handler."""
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            detail=exc.detail,
            error_code=f"HTTP_{exc.status_code}",
        ).model_dump(),
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """General exception handler."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            detail="Internal server error",
            error_code="INTERNAL_ERROR",
        ).model_dump(),
    )


# ==================== Include Routers ====================

app.include_router(basic_router)
app.include_router(access_router)
app.include_router(auth_router)
app.include_router(rate_router)
app.include_router(behavior_router)
app.include_router(content_router)
app.include_router(advanced_router)
app.include_router(admin_router)
app.include_router(test_router)


# ==================== Startup/Shutdown Events ====================


@app.on_event("startup")
async def startup_event() -> None:
    """Initialize services on startup."""
    logger.info("FastAPI Guard Example starting up...")
    logger.info("Security features enabled:")
    logger.info(f"  - Rate limiting: {security_config.enable_rate_limiting}")
    logger.info(f"  - IP banning: {security_config.enable_ip_banning}")
    logger.info(
        f"  - Penetration detection: {security_config.enable_penetration_detection}"
    )  # noqa: E501
    logger.info(f"  - Redis: {security_config.enable_redis}")
    logger.info(f"  - Agent: {security_config.enable_agent}")


@app.on_event("shutdown")
async def shutdown_event() -> None:
    """Cleanup on shutdown."""
    logger.info("FastAPI Guard Example shutting down...")


# ==================== Main Execution ====================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
