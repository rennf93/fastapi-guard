import logging
import os
from typing import Optional

from fastapi import FastAPI, Request, Query
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel

from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# Response Models
class MessageResponse(BaseModel):
    message: str

    class Config:
        json_schema_extra = {
            "example": {"message": "Hello World"}
        }


class IPResponse(BaseModel):
    ip: str

    class Config:
        json_schema_extra = {
            "example": {"ip": "127.0.0.1"}
        }


class TestResponse(BaseModel):
    message: str
    request_params: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "message": "Test endpoint",
                "request_params": "test_value"
            }
        }


class ErrorResponse(BaseModel):
    detail: str

    class Config:
        json_schema_extra = {
            "example": {"detail": "Request blocked"}
        }


# Initialize
app = FastAPI(
    title="FastAPI Guard Playground",
    description="""
    This is a playground to test FastAPI Guard middleware features.

    FastAPI Guard is a security middleware for FastAPI applications that provides:
    * IP whitelist/blacklist filtering
    * Rate limiting
    * Penetration detection and prevention
    * Auto-banning of suspicious IPs
    * Geolocation-based filtering
    * Cloud provider IP blocking
    * User agent filtering
    * And more!

    Use the test endpoints below to experiment with different security scenarios.
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)


IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")


# TODO: Adjust the following config as per your needs.
config = SecurityConfig(
    # Whitelist/Blacklist
    whitelist=["0.0.0.0", "0.0.0.0/0"],
    blacklist=["192.168.0.1/32", "10.0.0.100/32"],
    # Rate Limiting
    rate_limit=5,
    rate_limit_window=60,
    # Auto-ban Configuration
    enable_ip_banning=True,
    enable_penetration_detection=True,
    auto_ban_threshold=5,
    auto_ban_duration=60,
    # Excluded Paths
    exclude_paths=[
        "/docs",
        "/redoc",
        "/openapi.json",
        "/openapi.yaml",
        "/favicon.ico",
        "/static",
    ],
    # User Agent settings
    blocked_user_agents=["badbot", "malicious-crawler"],
    # IPInfo integration
    ipinfo_token=IPINFO_TOKEN,
    blocked_countries=["CN", "RU"],
    # Redis integration
    # NOTE: enable_redis=True by default
    redis_url="redis://localhost:6379",
    redis_prefix="fastapi_guard",
)
app.add_middleware(SecurityMiddleware, config=config)


# Test endpoints
@app.get(
    "/",
    response_model=MessageResponse,
    summary="Basic endpoint",
    description="Basic endpoint to test connectivity, whitelist, blacklist, rate limiting, excluded paths, etc.",
    responses={
        200: {"description": "Successful response", "model": MessageResponse},
        429: {"description": "Too many requests", "model": ErrorResponse},
        403: {"description": "IP has been banned", "model": ErrorResponse},
    },
    tags=["Basic Tests"],
)
async def root():
    """
    Simple endpoint that returns a hello message.

    This endpoint can be used to test:
    - Rate limiting (make multiple requests in a short time)
    - IP blocking (if your IP is in the blacklist)
    - Auto-banning (if you've triggered the security middleware)
    """
    return {"message": "Hello World"}


@app.get(
    "/ip",
    response_model=IPResponse,
    summary="Get client IP address",
    description="Returns the client's IP address as seen by the server.",
    responses={
        200: {"description": "Successful response with IP address", "model": IPResponse},
    },
    tags=["Information"],
)
async def get_ip(request: Request):
    """
    Returns the client's IP address.

    This can be useful to see which IP the security middleware is evaluating.
    If you're using proxies, you might want to check X-Forwarded-For headers.
    """
    return {"ip": request.client.host}


@app.get(
    "/test",
    response_model=TestResponse,
    summary="Test endpoint for penetration detection",
    description="This endpoint accepts various query parameters that can trigger security alerts.",
    responses={
        200: {"description": "Request accepted", "model": TestResponse},
        403: {"description": "IP has been banned", "model": ErrorResponse},
    },
    tags=["Security Tests"],
)
async def test_endpoint(
    input: Optional[str] = Query(
        None,
        description="Parameter to test XSS attacks",
        example="<script>alert(1)</script>"
    ),
    query: Optional[str] = Query(
        None,
        description="Parameter to test SQL injection",
        example="SELECT * FROM users"
    ),
    path: Optional[str] = Query(
        None,
        description="Parameter to test path traversal",
        example="../../../etc/passwd"
    ),
    cmd: Optional[str] = Query(
        None,
        description="Parameter to test command injection",
        example=";ls;pwd;"
    )
):
    """
    Test endpoint to trigger penetration detection.

    This endpoint accepts various parameters that can trigger security alerts:

    - **input**: Used to test XSS payload detection
    - **query**: Used to test SQL injection detection
    - **path**: Used to test path traversal detection
    - **cmd**: Used to test command injection detection
    """
    request_params = input or query or path or cmd
    return {"message": "Test endpoint", "request_params": request_params}


# TODO: Unban IP (reset IPBanManager) endpoint.


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    openapi_schema["components"]["securitySchemes"] = {
        "IPFiltering": {
            "type": "apiKey",
            "in": "header",
            "name": "X-Forwarded-For",
            "description": "IP filtering based on client IP or X-Forwarded-For header"
        },
        "UserAgentFiltering": {
            "type": "apiKey",
            "in": "header",
            "name": "User-Agent",
            "description": "User agent filtering based on User-Agent header"
        }
    }

    if "paths" in openapi_schema:
        for path in openapi_schema["paths"].values():
            for operation in path.values():
                operation["security"] = [{"IPFiltering": []}, {"UserAgentFiltering": []}]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
