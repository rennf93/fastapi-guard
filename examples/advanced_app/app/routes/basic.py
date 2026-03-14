from ipaddress import ip_address
from typing import Any

from fastapi import APIRouter, Body, Request

from app.models import BasicHealthResponse, IPInfoResponse, MessageResponse

router = APIRouter(prefix="/basic", tags=["Basic Features"])


@router.get(
    "/",
    response_model=MessageResponse,
    status_code=200,
    summary="Basic Features Root",
    description="Entry point for basic feature demonstrations.",
)
async def basic_root() -> MessageResponse:
    return MessageResponse(message="Basic features endpoint")


@router.get(
    "/ip",
    response_model=IPInfoResponse,
    status_code=200,
    summary="Client IP Information",
    description=(
        "Returns the detected client IP address along with geolocation and cloud"
        "provider metadata."
    ),
)
async def get_ip_info(request: Request) -> IPInfoResponse:
    client_ip = "unknown"
    if request.client:
        try:
            client_ip = str(ip_address(request.client.host))
        except ValueError:
            client_ip = request.client.host

    return IPInfoResponse(
        ip=client_ip,
        country="US",
        city="Example City",
        region="Example Region",
        is_vpn=False,
        is_cloud=False,
    )


@router.get(
    "/health",
    response_model=BasicHealthResponse,
    status_code=200,
    summary="Basic Health Check",
    description="Lightweight health check returning only the service status.",
)
async def health_check() -> BasicHealthResponse:
    return BasicHealthResponse(status="healthy")


@router.post(
    "/echo",
    response_model=MessageResponse,
    status_code=200,
    summary="Echo Request",
    description=(
        "Echoes back the request data, headers, method, and URL. Useful for debugging"
        "and inspecting how requests are received after passing through the security"
        "middleware."
    ),
)
async def echo_request(
    request: Request,
    data: dict[str, Any] = Body(...),  # noqa: B008
) -> MessageResponse:
    return MessageResponse(
        message="Echo response",
        details={
            "data": data,
            "headers": dict(request.headers),
            "method": request.method,
            "url": str(request.url),
        },
    )
