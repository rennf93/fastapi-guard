from typing import Any, cast

import pytest

from guard.handlers.ipinfo_handler import IPInfoManager
from guard.models import SecurityConfig
from guard.protocols.geo_ip_protocol import GeoIPHandler


def test_security_config_validation() -> None:
    valid_config = SecurityConfig(
        ipinfo_token="valid_token",
        whitelist=["10.0.0.0/24", "192.168.1.1"],
        blacklist=["203.0.113.0/25"],
    )
    assert valid_config.whitelist == ["10.0.0.0/24", "192.168.1.1"]


def test_invalid_ip_validation() -> None:
    with pytest.raises(ValueError):
        SecurityConfig(
            ipinfo_token="test", whitelist=["invalid.ip"], blacklist=["256.0.0.0"]
        )


def test_cloud_provider_validation() -> None:
    config = SecurityConfig(
        ipinfo_token="test", block_cloud_providers={"AWS", "INVALID"}
    )
    assert config.block_cloud_providers == {"AWS"}


def test_security_config_none_whitelist() -> None:
    """Test that None whitelist is handled correctly"""
    config = SecurityConfig(ipinfo_token="test", whitelist=None)
    assert config.whitelist is None


def test_none_cloud_providers() -> None:
    """Test that None cloud_providers is handled correctly"""
    config = SecurityConfig(ipinfo_token="test", block_cloud_providers=None)
    assert config.block_cloud_providers == set()


def test_missing_ipinfo_token() -> None:
    """Test that missing ipinfo_token and geo_ip_handler raises a ValueError"""
    with pytest.raises(ValueError):
        SecurityConfig(blocked_countries=["US"])

    with pytest.raises(ValueError):
        SecurityConfig(whitelist_countries=["US"])

    with pytest.raises(ValueError):
        SecurityConfig(blocked_countries=["US"], whitelist_countries=["US"])


class ValidGeoIPHandler:
    @property
    def is_initialized(self) -> bool:
        return True

    async def initialize(self) -> None:
        return

    async def initialize_redis(self, redis_handler: Any) -> None:
        return

    def get_country(self, ip: str) -> str | None:
        return None


def test_geo_ip_handler_validation() -> None:
    ipinfo = IPInfoManager(token="test")
    config = SecurityConfig(geo_ip_handler=ipinfo)
    assert config.geo_ip_handler == ipinfo

    valid_instance = ValidGeoIPHandler()
    config = SecurityConfig(geo_ip_handler=valid_instance)
    assert config.geo_ip_handler == valid_instance

    config = SecurityConfig(geo_ip_handler=None)
    assert config.geo_ip_handler is None

    class InvalidGeoIPHandler:
        pass

    invalid_handler = cast(GeoIPHandler, InvalidGeoIPHandler())
    with pytest.raises(ValueError):
        SecurityConfig(geo_ip_handler=invalid_handler)


def test_geo_ip_handler_deprecated_fallback() -> None:
    config = SecurityConfig(ipinfo_token="test", whitelist_countries=["US"])
    assert isinstance(config.geo_ip_handler, IPInfoManager)


@pytest.mark.asyncio
async def test_geo_ip_handler_async_methods() -> None:
    """Test that async methods in GeoIPHandler are called properly"""
    handler = ValidGeoIPHandler()

    # Test initialize method
    await handler.initialize()
    assert handler.is_initialized is True

    # Test initialize_redis method
    mock_redis = object()  # Simple mock object
    await handler.initialize_redis(mock_redis)

    # Test get_country method
    result = handler.get_country("192.168.1.1")
    assert result is None
