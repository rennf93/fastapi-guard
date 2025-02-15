import pytest
from guard.models import SecurityConfig



def test_security_config_validation():
    valid_config = SecurityConfig(
        ipinfo_token="valid_token",
        whitelist=[
            "10.0.0.0/24",
            "192.168.1.1"
        ],
        blacklist=["203.0.113.0/25"]
    )
    assert valid_config.whitelist == [
        "10.0.0.0/24",
        "192.168.1.1"
    ]


def test_invalid_ip_validation():
    with pytest.raises(ValueError):
        SecurityConfig(
            ipinfo_token="test",
            whitelist=["invalid.ip"],
            blacklist=["256.0.0.0"]
        )


def test_cloud_provider_validation():
    config = SecurityConfig(
        ipinfo_token="test",
        block_cloud_providers={
            "AWS",
            "INVALID"
        }
    )
    assert config.block_cloud_providers == {"AWS"}