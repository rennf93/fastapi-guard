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

    async def initialize_agent(self, agent_handler: Any) -> None:
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

    # Test initialize_agent method
    mock_agent = object()  # Simple mock object
    await handler.initialize_agent(mock_agent)

    # Test get_country method
    result = handler.get_country("192.168.1.1")
    assert result is None


def test_validate_trusted_proxies() -> None:
    """Test validation of trusted proxies."""
    # Valid IPs
    config = SecurityConfig(trusted_proxies=["127.0.0.1", "192.168.1.0/24"])
    assert "127.0.0.1" in config.trusted_proxies
    assert "192.168.1.0/24" in config.trusted_proxies

    # Invalid IP
    with pytest.raises(ValueError, match="Invalid proxy IP or CIDR range"):
        SecurityConfig(trusted_proxies=["invalid-ip"])

    # Empty list is allowed
    config = SecurityConfig(trusted_proxies=[])
    assert config.trusted_proxies == []


def test_validate_proxy_depth() -> None:
    """Test validation of trusted proxy depth."""
    # Valid depth
    config = SecurityConfig(trusted_proxy_depth=2)
    assert config.trusted_proxy_depth == 2

    # Invalid depth
    with pytest.raises(ValueError, match="trusted_proxy_depth must be at least 1"):
        SecurityConfig(trusted_proxy_depth=0)
