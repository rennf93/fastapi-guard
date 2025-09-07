import json
from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard.handlers.security_headers_handler import (
    SecurityHeadersManager,
    security_headers_manager,
)


@pytest.fixture
async def headers_manager() -> AsyncGenerator[SecurityHeadersManager, None]:
    """Create a fresh headers manager for testing."""
    # Save the original redis_handler
    original_redis = security_headers_manager.redis_handler
    # Set to None to avoid warnings during reset
    security_headers_manager.redis_handler = None

    # Reset before test
    await security_headers_manager.reset()

    yield security_headers_manager

    # Clean up: set to None before reset to avoid warnings
    security_headers_manager.redis_handler = None
    await security_headers_manager.reset()

    # Restore the original redis_handler
    security_headers_manager.redis_handler = original_redis


@pytest.mark.asyncio
async def test_initialize_redis(headers_manager: SecurityHeadersManager) -> None:
    """Test Redis initialization for headers manager."""
    mock_redis = AsyncMock()
    mock_redis.get_key = AsyncMock(return_value=None)

    await headers_manager.initialize_redis(mock_redis)

    assert headers_manager.redis_handler == mock_redis
    # Should attempt to load cached config
    mock_redis.get_key.assert_called()


@pytest.mark.asyncio
async def test_load_cached_config_from_redis(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test loading cached configuration from Redis."""
    mock_redis = AsyncMock()

    # Mock cached CSP config
    csp_config = {
        "default-src": ["'self'"],
        "script-src": ["'self'", "https://cdn.com"],
    }
    mock_redis.get_key = AsyncMock(
        side_effect=[
            json.dumps(csp_config),  # CSP config
            json.dumps(
                {"max_age": 31536000, "include_subdomains": True}
            ),  # HSTS config
            json.dumps({"X-Custom": "value"}),  # Custom headers
        ]
    )

    headers_manager.redis_handler = mock_redis
    await headers_manager._load_cached_config()

    assert headers_manager.csp_config == csp_config
    assert headers_manager.hsts_config is not None
    assert headers_manager.hsts_config["max_age"] == 31536000
    assert headers_manager.custom_headers["X-Custom"] == "value"

    # Verify Redis calls
    assert mock_redis.get_key.call_count == 3
    mock_redis.get_key.assert_any_call("security_headers", "csp_config")
    mock_redis.get_key.assert_any_call("security_headers", "hsts_config")
    mock_redis.get_key.assert_any_call("security_headers", "custom_headers")


@pytest.mark.asyncio
async def test_load_cached_config_redis_error(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test handling Redis errors when loading cached config."""
    mock_redis = AsyncMock()
    mock_redis.get_key = AsyncMock(side_effect=Exception("Redis connection error"))

    headers_manager.redis_handler = mock_redis

    # Should not raise, just log warning
    await headers_manager._load_cached_config()

    # Config should remain unchanged
    assert headers_manager.csp_config is None
    assert headers_manager.hsts_config is None


@pytest.mark.asyncio
async def test_load_cached_config_no_redis_handler(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test _load_cached_config returns early when no Redis handler."""
    # Ensure redis_handler is None
    headers_manager.redis_handler = None

    # Should return early without any errors
    await headers_manager._load_cached_config()

    # Config should remain as initialized
    assert headers_manager.csp_config is None
    assert headers_manager.hsts_config is None


@pytest.mark.asyncio
async def test_cache_configuration_to_redis(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test caching configuration to Redis."""
    mock_redis = AsyncMock()
    mock_redis.set_key = AsyncMock()

    headers_manager.redis_handler = mock_redis
    headers_manager.csp_config = {"default-src": ["'self'"]}
    headers_manager.hsts_config = {"max_age": 31536000}
    headers_manager.custom_headers = {"X-Custom": "value"}

    await headers_manager._cache_configuration()

    # Verify all configs were cached
    assert mock_redis.set_key.call_count == 3
    mock_redis.set_key.assert_any_call(
        "security_headers",
        "csp_config",
        json.dumps({"default-src": ["'self'"]}),
        ttl=86400,
    )
    mock_redis.set_key.assert_any_call(
        "security_headers", "hsts_config", json.dumps({"max_age": 31536000}), ttl=86400
    )
    mock_redis.set_key.assert_any_call(
        "security_headers",
        "custom_headers",
        json.dumps({"X-Custom": "value"}),
        ttl=86400,
    )


@pytest.mark.asyncio
async def test_cache_configuration_redis_error(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test handling Redis errors when caching configuration."""
    mock_redis = AsyncMock()
    mock_redis.set_key = AsyncMock(side_effect=Exception("Redis write error"))

    headers_manager.redis_handler = mock_redis
    headers_manager.csp_config = {"default-src": ["'self'"]}

    # Should not raise, just log warning
    await headers_manager._cache_configuration()


@pytest.mark.asyncio
async def test_cache_configuration_no_redis(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test caching when Redis is not configured."""
    headers_manager.redis_handler = None
    headers_manager.csp_config = {"default-src": ["'self'"]}

    # Should return early without error
    await headers_manager._cache_configuration()


@pytest.mark.asyncio
async def test_cache_configuration_partial_config(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test caching when only some configurations are set."""
    mock_redis = AsyncMock()
    mock_redis.set_key = AsyncMock()

    mock_conn = AsyncMock()
    mock_conn.keys = AsyncMock(return_value=[])
    mock_conn.delete = AsyncMock()

    mock_context = AsyncMock()
    mock_context.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_context.__aexit__ = AsyncMock()

    mock_redis.get_connection = AsyncMock(return_value=mock_context)
    mock_redis.config = MagicMock()
    mock_redis.config.redis_prefix = "fastapi_guard:"

    headers_manager.redis_handler = mock_redis
    # Only set CSP config, not HSTS or custom headers
    headers_manager.csp_config = {"default-src": ["'self'"]}
    headers_manager.hsts_config = None
    headers_manager.custom_headers = {}

    await headers_manager._cache_configuration()

    # Should only cache CSP config
    mock_redis.set_key.assert_called_once_with(
        "security_headers",
        "csp_config",
        json.dumps({"default-src": ["'self'"]}),
        ttl=86400,
    )


@pytest.mark.asyncio
async def test_reset_with_redis_proper_async(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test reset functionality with Redis using proper async context manager."""
    with patch.object(headers_manager, "redis_handler") as mock_redis:
        mock_conn = AsyncMock()
        mock_conn.keys = AsyncMock(
            return_value=[
                b"fastapi_guard:security_headers:csp_config",
                b"fastapi_guard:security_headers:custom_headers",
            ]
        )
        mock_conn.delete = AsyncMock()

        # Setup context manager
        mock_context = AsyncMock()
        mock_context.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_context.__aexit__ = AsyncMock()

        mock_redis.get_connection.return_value = mock_context
        mock_redis.config.redis_prefix = "fastapi_guard:"

        headers_manager.custom_headers = {"X-Test": "value"}
        headers_manager.csp_config = {"default-src": ["'self'"]}

        await headers_manager.reset()

        # Verify state is reset
        assert len(headers_manager.custom_headers) == 0
        assert headers_manager.csp_config is None


@pytest.mark.asyncio
async def test_reset_with_empty_redis_keys(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test reset when Redis returns no keys."""
    with patch.object(headers_manager, "redis_handler") as mock_redis:
        mock_conn = AsyncMock()
        mock_conn.keys = AsyncMock(return_value=[])  # No keys found
        mock_conn.delete = AsyncMock()

        # Setup context manager
        mock_context = AsyncMock()
        mock_context.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_context.__aexit__ = AsyncMock()

        mock_redis.get_connection.return_value = mock_context
        mock_redis.config.redis_prefix = "fastapi_guard:"

        headers_manager.custom_headers = {"X-Test": "value"}

        await headers_manager.reset()

        # Verify state is reset
        assert len(headers_manager.custom_headers) == 0

        # keys should be called but delete should not (no keys to delete)
        mock_conn.keys.assert_called_once_with("fastapi_guard:security_headers:*")
        mock_conn.delete.assert_not_called()


@pytest.mark.asyncio
async def test_reset_redis_error(headers_manager: SecurityHeadersManager) -> None:
    """Test reset with Redis errors."""
    # Create a context manager that fails on connection
    mock_context = AsyncMock()
    mock_context.__aenter__ = AsyncMock(side_effect=Exception("Connection failed"))
    mock_context.__aexit__ = AsyncMock()

    # Create mock redis that fails on connection
    mock_redis = MagicMock()
    mock_redis.get_connection.return_value = mock_context
    mock_redis.config.redis_prefix = "fastapi_guard:"

    headers_manager.redis_handler = mock_redis
    headers_manager.custom_headers = {"X-Test": "value"}

    # Should not raise, just log warning
    await headers_manager.reset()

    # Local state should still be reset
    assert len(headers_manager.custom_headers) == 0
    assert headers_manager.enabled


@pytest.mark.asyncio
async def test_reset_without_redis(headers_manager: SecurityHeadersManager) -> None:
    """Test reset without Redis configured."""
    headers_manager.redis_handler = None
    headers_manager.custom_headers = {"X-Test": "value"}
    headers_manager.csp_config = {"default-src": ["'self'"]}

    await headers_manager.reset()

    # State should be reset
    assert len(headers_manager.custom_headers) == 0
    assert headers_manager.csp_config is None


@pytest.mark.asyncio
async def test_initialize_redis_and_cache_configuration(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test Redis initialization triggers caching of configuration."""
    mock_redis = AsyncMock()
    mock_redis.get_key = AsyncMock(return_value=None)
    mock_redis.set_key = AsyncMock()

    mock_conn = AsyncMock()
    mock_conn.keys = AsyncMock(return_value=[])
    mock_conn.delete = AsyncMock()

    mock_context = AsyncMock()
    mock_context.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_context.__aexit__ = AsyncMock()

    mock_redis.get_connection = AsyncMock(return_value=mock_context)
    mock_redis.config = MagicMock()
    mock_redis.config.redis_prefix = "fastapi_guard:"

    # Set some configuration before initialization
    headers_manager.configure(
        csp={"default-src": ["'self'"]},
        hsts_max_age=31536000,
        custom_headers={"X-Custom": "value"},
    )

    await headers_manager.initialize_redis(mock_redis)

    assert headers_manager.redis_handler == mock_redis

    # Should have tried to load cached config
    assert mock_redis.get_key.call_count == 3  # CSP, HSTS, custom headers

    # Should have cached the configuration
    assert mock_redis.set_key.call_count == 3  # CSP, HSTS, custom headers
