import pytest

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
    """Test that missing ipinfo_token raises a ValueError"""
    with pytest.raises(ValueError):
        SecurityConfig(ipinfo_token=None, blocked_countries=["US"])

    with pytest.raises(ValueError):
        SecurityConfig(ipinfo_token=None, whitelist_countries=["US"])

    with pytest.raises(ValueError):
        SecurityConfig(
            ipinfo_token=None, blocked_countries=["US"], whitelist_countries=["US"]
        )
