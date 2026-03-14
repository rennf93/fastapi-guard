from fastapi import APIRouter

from app.models import MessageResponse
from app.security import guard

router = APIRouter(prefix="/access", tags=["Access Control"])


@router.get(
    "/ip-whitelist",
    response_model=MessageResponse,
    status_code=200,
    summary="IP Whitelist Enforcement",
    description=(
        "Only allows access from whitelisted IP addresses or CIDR ranges. Requests from"
        "all other IPs are rejected with 403."
    ),
    responses={403: {"description": "IP not in whitelist"}},
)
@guard.require_ip(whitelist=["127.0.0.1", "10.0.0.0/8"])
async def ip_whitelist_only() -> MessageResponse:
    return MessageResponse(message="Access granted from whitelisted IP")


@router.get(
    "/ip-blacklist",
    response_model=MessageResponse,
    status_code=200,
    summary="IP Blacklist Enforcement",
    description=(
        "Blocks access from blacklisted IP addresses or CIDR ranges. All other IPs are"
        "allowed through."
    ),
    responses={403: {"description": "IP is blacklisted"}},
)
@guard.require_ip(blacklist=["192.168.1.0/24", "172.16.0.0/12"])
async def ip_blacklist_demo() -> MessageResponse:
    return MessageResponse(message="Access granted - you're not blacklisted")


@router.get(
    "/country-block",
    response_model=MessageResponse,
    status_code=200,
    summary="Country Blocking",
    description=(
        "Blocks requests originating from specified countries using ISO 3166-1 alpha-2"
        "codes. Geo IP lookup is performed against a local MaxMind database."
    ),
    responses={403: {"description": "Country is blocked"}},
)
@guard.block_countries(["CN", "RU", "KP"])
async def block_specific_countries() -> MessageResponse:
    return MessageResponse(message="Access granted - your country is not blocked")


@router.get(
    "/country-allow",
    response_model=MessageResponse,
    status_code=200,
    summary="Country Allowlist",
    description=(
        "Only allows requests from specified countries. All other countries are"
        " blocked."
        "Uses local MaxMind database for geo IP resolution."
    ),
    responses={403: {"description": "Country not in allowlist"}},
)
@guard.allow_countries(["US", "CA", "GB", "AU"])
async def allow_specific_countries() -> MessageResponse:
    return MessageResponse(message="Access granted from allowed country")


@router.get(
    "/no-cloud",
    response_model=MessageResponse,
    status_code=200,
    summary="Block All Cloud Providers",
    description=(
        "Blocks requests originating from AWS, GCP, and Azure IP ranges. Cloud IP"
        " ranges"
        "are refreshed hourly and matched in-memory via CIDR."
    ),
    responses={403: {"description": "Request from cloud provider IP"}},
)
@guard.block_clouds()
async def block_all_clouds() -> MessageResponse:
    return MessageResponse(message="Access granted - not from cloud provider")


@router.get(
    "/no-aws",
    response_model=MessageResponse,
    status_code=200,
    summary="Block AWS Only",
    description=(
        "Blocks requests originating from AWS IP ranges while allowing GCP and Azure."
        "Demonstrates selective cloud provider blocking."
    ),
    responses={403: {"description": "Request from AWS IP range"}},
)
@guard.block_clouds(["AWS"])
async def block_aws_only() -> MessageResponse:
    return MessageResponse(message="Access granted - not from AWS")


@router.get(
    "/bypass-demo",
    response_model=MessageResponse,
    status_code=200,
    summary="Bypass Specific Checks",
    description=(
        "Demonstrates selectively bypassing security checks on a per-route basis. This"
        "endpoint skips rate limiting and geo checks while all other security checks"
        "remain active."
    ),
)
@guard.bypass(["rate_limit", "geo_check"])
async def bypass_specific_checks() -> MessageResponse:
    return MessageResponse(
        message="This endpoint bypasses rate limiting and geo checks",
        details={"bypassed_checks": ["rate_limit", "geo_check"]},
    )
