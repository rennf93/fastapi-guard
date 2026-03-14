from ipaddress import ip_address
from typing import Any

from fastapi import APIRouter, Body, Request

from app.models import IPInfoResponse, MessageResponse

router = APIRouter(prefix="/basic", tags=["Basic Features"])


@router.get("/", response_model=MessageResponse)
async def basic_root() -> MessageResponse:
    return MessageResponse(message="Basic features endpoint")


@router.get("/ip", response_model=IPInfoResponse)
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


@router.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "healthy"}


@router.post("/echo", response_model=MessageResponse)
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
