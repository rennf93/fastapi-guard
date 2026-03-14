import ipaddress
import time
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import ValidationError

from guard.handlers.cloud_handler import cloud_handler
from guard.models import SecurityConfig


@pytest.fixture(autouse=True)
def reset_cloud_handler() -> None:
    cloud_handler.ip_ranges = {"AWS": set(), "GCP": set(), "Azure": set()}
    cloud_handler.last_updated = {"AWS": None, "GCP": None, "Azure": None}
    cloud_handler.redis_handler = None
    cloud_handler.agent_handler = None


def test_config_default_value() -> None:
    config = SecurityConfig(enable_redis=False)
    assert config.cloud_ip_refresh_interval == 3600


def test_config_custom_value() -> None:
    config = SecurityConfig(enable_redis=False, cloud_ip_refresh_interval=120)
    assert config.cloud_ip_refresh_interval == 120


def test_config_rejects_below_minimum() -> None:
    with pytest.raises(ValidationError, match="greater than or equal to 60"):
        SecurityConfig(enable_redis=False, cloud_ip_refresh_interval=30)


def test_config_rejects_above_maximum() -> None:
    with pytest.raises(ValidationError, match="less than or equal to 86400"):
        SecurityConfig(enable_redis=False, cloud_ip_refresh_interval=100000)


def test_config_accepts_boundary_values() -> None:
    low = SecurityConfig(enable_redis=False, cloud_ip_refresh_interval=60)
    assert low.cloud_ip_refresh_interval == 60
    high = SecurityConfig(enable_redis=False, cloud_ip_refresh_interval=86400)
    assert high.cloud_ip_refresh_interval == 86400


@pytest.mark.asyncio
async def test_cloud_ip_refresh_check_uses_config_value() -> None:
    from unittest.mock import MagicMock

    from guard.core.checks.implementations.cloud_ip_refresh import (
        CloudIpRefreshCheck,
    )

    config = SecurityConfig(
        enable_redis=False,
        block_cloud_providers={"AWS"},
        cloud_ip_refresh_interval=120,
    )
    middleware = MagicMock()
    middleware.config = config
    middleware.last_cloud_ip_refresh = time.time() - 130
    middleware.refresh_cloud_ip_ranges = AsyncMock()

    check = CloudIpRefreshCheck(middleware)
    request = MagicMock()
    await check.check(request)

    middleware.refresh_cloud_ip_ranges.assert_awaited_once()


@pytest.mark.asyncio
async def test_cloud_ip_refresh_check_skips_within_interval() -> None:
    from unittest.mock import MagicMock

    from guard.core.checks.implementations.cloud_ip_refresh import (
        CloudIpRefreshCheck,
    )

    config = SecurityConfig(
        enable_redis=False,
        block_cloud_providers={"AWS"},
        cloud_ip_refresh_interval=120,
    )
    middleware = MagicMock()
    middleware.config = config
    middleware.last_cloud_ip_refresh = time.time() - 60
    middleware.refresh_cloud_ip_ranges = AsyncMock()

    check = CloudIpRefreshCheck(middleware)
    request = MagicMock()
    await check.check(request)

    middleware.refresh_cloud_ip_ranges.assert_not_awaited()


@pytest.mark.asyncio
async def test_refresh_async_passes_ttl_to_redis() -> None:
    mock_redis = AsyncMock()
    mock_redis.get_key = AsyncMock(return_value=None)
    mock_redis.set_key = AsyncMock()

    cloud_handler.redis_handler = mock_redis

    test_ranges = {ipaddress.ip_network("10.0.0.0/8")}
    with patch(
        "guard.handlers.cloud_handler.fetch_aws_ip_ranges",
        return_value=test_ranges,
    ):
        await cloud_handler.refresh_async({"AWS"}, ttl=7200)

    mock_redis.set_key.assert_awaited_once()
    call_kwargs = mock_redis.set_key.call_args
    assert call_kwargs.kwargs["ttl"] == 7200


def test_log_range_changes_logs_when_changed(caplog: pytest.LogCaptureFixture) -> None:
    old = {ipaddress.ip_network("10.0.0.0/8")}
    new = {
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
    }

    import logging

    with caplog.at_level(logging.INFO):
        cloud_handler._log_range_changes("AWS", old, new)

    assert "+1 added, -0 removed" in caplog.text


def test_log_range_changes_silent_when_unchanged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    ranges = {ipaddress.ip_network("10.0.0.0/8")}

    import logging

    with caplog.at_level(logging.INFO):
        cloud_handler._log_range_changes("AWS", ranges, ranges)

    assert "Cloud IP range update" not in caplog.text
