from fastapi import APIRouter

from app.models import MessageResponse
from app.security import guard

router = APIRouter(prefix="/access", tags=["Access Control"])


@router.get("/ip-whitelist", response_model=MessageResponse)
@guard.require_ip(whitelist=["127.0.0.1", "10.0.0.0/8"])
async def ip_whitelist_only() -> MessageResponse:
    return MessageResponse(message="Access granted from whitelisted IP")


@router.get("/ip-blacklist", response_model=MessageResponse)
@guard.require_ip(blacklist=["192.168.1.0/24", "172.16.0.0/12"])
async def ip_blacklist_demo() -> MessageResponse:
    return MessageResponse(message="Access granted - you're not blacklisted")


@router.get("/country-block", response_model=MessageResponse)
@guard.block_countries(["CN", "RU", "KP"])
async def block_specific_countries() -> MessageResponse:
    return MessageResponse(message="Access granted - your country is not blocked")


@router.get("/country-allow", response_model=MessageResponse)
@guard.allow_countries(["US", "CA", "GB", "AU"])
async def allow_specific_countries() -> MessageResponse:
    return MessageResponse(message="Access granted from allowed country")


@router.get("/no-cloud", response_model=MessageResponse)
@guard.block_clouds()
async def block_all_clouds() -> MessageResponse:
    return MessageResponse(message="Access granted - not from cloud provider")


@router.get("/no-aws", response_model=MessageResponse)
@guard.block_clouds(["AWS"])
async def block_aws_only() -> MessageResponse:
    return MessageResponse(message="Access granted - not from AWS")


@router.get("/bypass-demo", response_model=MessageResponse)
@guard.bypass(["rate_limit", "geo_check"])
async def bypass_specific_checks() -> MessageResponse:
    return MessageResponse(
        message="This endpoint bypasses rate limiting and geo checks",
        details={"bypassed_checks": ["rate_limit", "geo_check"]},
    )
