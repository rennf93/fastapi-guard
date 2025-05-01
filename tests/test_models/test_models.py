from typing import Any

import pytest

from guard.handlers.ipinfo_handler import IPInfoManager
from guard.models import SecurityConfig


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
    """Test that missing ipinfo_token and geographical_ip_handler raises a ValueError"""
    with pytest.raises(ValueError):
        SecurityConfig(blocked_countries=["US"])

    with pytest.raises(ValueError):
        SecurityConfig(whitelist_countries=["US"])

    with pytest.raises(ValueError):
        SecurityConfig(blocked_countries=["US"], whitelist_countries=["US"])


def test_geographical_ip_handler_validation() -> None:
    ipinfo = IPInfoManager(token="test")
    config = SecurityConfig(geographical_ip_handler=ipinfo)
    assert config.geographical_ip_handler == ipinfo

    class ValidGeographicalIPHandler:
        @property
        def is_initialized(self) -> bool:
            return True

        async def initialize(self) -> None:
            return

        async def initialize_redis(self, redis_handler: Any) -> None:
            return

        def get_country(self, ip: str) -> str | None:
            return None

    valid_instance = ValidGeographicalIPHandler()
    config = SecurityConfig(geographical_ip_handler=valid_instance)
    assert config.geographical_ip_handler == valid_instance

    config = SecurityConfig(geographical_ip_handler=None)
    assert config.geographical_ip_handler is None

    class InvalidGeographicalIPHandler:
        pass

    with pytest.raises(ValueError):
        SecurityConfig(geographical_ip_handler=InvalidGeographicalIPHandler())  # type: ignore


def test_geographical_ip_handler_deprecated_fallback() -> None:
    config = SecurityConfig(ipinfo_token="test", whitelist_countries=["US"])
    assert isinstance(config.geographical_ip_handler, IPInfoManager)
