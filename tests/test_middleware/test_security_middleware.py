import logging
import os
import time
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import pytest
from cachetools import TTLCache
from fastapi import FastAPI, Request, Response, status
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport

from guard.handlers.cloud_handler import cloud_handler
from guard.handlers.ipban_handler import ip_ban_manager
from guard.handlers.ipinfo_handler import IPInfoManager
from guard.handlers.ratelimit_handler import rate_limit_handler
from guard.handlers.suspatterns_handler import sus_patterns_handler
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig

IPINFO_TOKEN = str(os.getenv("IPINFO_TOKEN"))


@pytest.mark.asyncio
async def test_rate_limiting() -> None:
    """
    Test the rate limiting functionality
    of the SecurityMiddleware.
    """
    app = FastAPI()
    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        rate_limit=2,
        rate_limit_window=1,
        enable_rate_limiting=True,
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/")
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

        handler = rate_limit_handler(config)
        handler.request_times.clear()

        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_ip_whitelist_blacklist() -> None:
    """
    Test the IP whitelist/blacklist
    functionality of the SecurityMiddleware.
    """
    app = FastAPI()
    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        whitelist=["127.0.0.1"],
        blacklist=["192.168.1.1"],
        enable_penetration_detection=False,
        trusted_proxies=["127.0.0.1"],
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/", headers={"X-Forwarded-For": "127.0.0.1"})
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.1"})
        assert response.status_code == status.HTTP_403_FORBIDDEN

        response = await client.get("/", headers={"X-Forwarded-For": "10.0.0.1"})
        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_user_agent_filtering() -> None:
    """
    Test the user agent filtering
    functionality of the SecurityMiddleware.
    """
    app = FastAPI()
    config = SecurityConfig(ipinfo_token=IPINFO_TOKEN, blocked_user_agents=[r"badbot"])
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/", headers={"User-Agent": "goodbot"})
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/", headers={"User-Agent": "badbot"})
        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_rate_limiting_multiple_ips(reset_state: None) -> None:
    """
    Test the rate limiting functionality
    of the SecurityMiddleware with multiple IPs.
    """
    app = FastAPI()
    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        rate_limit=2,
        rate_limit_window=1,
        enable_rate_limiting=True,
        whitelist=[],
        blacklist=[],
        enable_penetration_detection=False,
        trusted_proxies=["127.0.0.1"],
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        for i in range(1, 4):
            response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.1"})
            assert response.status_code == (
                status.HTTP_200_OK if i <= 2 else status.HTTP_429_TOO_MANY_REQUESTS
            )

        for i in range(1, 4):
            response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.5"})
            assert response.status_code == (
                status.HTTP_200_OK if i <= 2 else status.HTTP_429_TOO_MANY_REQUESTS
            )

        response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.1"})
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

        response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.5"})
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS


@pytest.mark.asyncio
async def test_middleware_multiple_configs() -> None:
    """
    Test the SecurityMiddleware
    with multiple configurations.
    """
    app = FastAPI()
    config1 = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        blocked_user_agents=[r"badbot"],
        enable_penetration_detection=False,
        trusted_proxies=["127.0.0.1"],
    )
    config2 = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        whitelist=["127.0.0.1"],
        blacklist=["192.168.1.1"],
        enable_penetration_detection=False,
        trusted_proxies=["127.0.0.1"],
    )

    app.add_middleware(SecurityMiddleware, config=config1)
    app.add_middleware(SecurityMiddleware, config=config2)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/", headers={"User-Agent": "badbot"})
        assert response.status_code == status.HTTP_403_FORBIDDEN

        response = await client.get("/", headers={"X-Forwarded-For": "127.0.0.1"})
        assert response.status_code == status.HTTP_200_OK
        response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.1"})
        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_custom_request_check() -> None:
    """
    Test the custom request check
    functionality of the SecurityMiddleware.
    """
    app = FastAPI()

    async def custom_check(request: Request) -> Response | None:
        if request.headers.get("X-Custom-Header") == "block":
            return Response("Custom block", status_code=status.HTTP_403_FORBIDDEN)
        return None

    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN, custom_request_check=custom_check
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/", headers={"X-Custom-Header": "block"})
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.text == "Custom block"

        response = await client.get("/", headers={"X-Custom-Header": "allow"})
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_custom_error_responses() -> None:
    """
    Test the custom error responses.
    """
    app = FastAPI()
    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        blacklist=["192.168.1.3"],
        custom_error_responses={
            403: "Custom Forbidden",
            429: "Custom Too Many Requests",
        },
        rate_limit=5,
        rate_limit_window=1,
        auto_ban_threshold=10,
        enable_penetration_detection=False,
        trusted_proxies=["127.0.0.1"],
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.3"})
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.text == "Custom Forbidden"

        for _ in range(5):
            response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.4"})
            assert response.status_code == status.HTTP_200_OK

        response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.4"})
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert response.text == "Custom Too Many Requests"


@pytest.mark.asyncio
async def test_cors_configuration() -> None:
    app = FastAPI()
    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["X-Custom-Header"],
        cors_allow_credentials=True,
        cors_expose_headers=["X-Custom-Header"],
        cors_max_age=600,
    )

    cors_added = SecurityMiddleware.configure_cors(app, config)
    assert cors_added, "CORS middleware was not added"

    client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    response = await client.options(
        "/",
        headers={
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-Custom-Header",
        },
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.headers["access-control-allow-origin"] == "https://example.com"
    assert "GET" in response.headers["access-control-allow-methods"]
    assert "X-Custom-Header" in response.headers["access-control-allow-headers"]
    assert response.headers["access-control-max-age"] == "600"


@pytest.mark.asyncio
async def test_cors_configuration_missing_expose_headers() -> None:
    """Test CORS configuration when expose-headers is not present"""
    app = FastAPI()
    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["X-Custom-Header"],
        cors_allow_credentials=True,
        # NOTE: No cors_expose_headers
        cors_max_age=600,
    )

    cors_added = SecurityMiddleware.configure_cors(app, config)
    assert cors_added, "CORS middleware was not added"

    client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    response = await client.options(
        "/",
        headers={
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-Custom-Header",
        },
    )

    assert "access-control-expose-headers" not in response.headers
    print("Warning: access-control-expose-headers not present in response")


@pytest.mark.asyncio
async def test_cloud_ip_blocking() -> None:
    app = FastAPI()
    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN, block_cloud_providers={"AWS", "GCP", "Azure"}
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    with patch.object(cloud_handler, "is_cloud_ip", return_value=True):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get(
                "/", headers={"X-Forwarded-For": "13.59.255.255"}
            )
            assert response.status_code == status.HTTP_403_FORBIDDEN

    with patch.object(cloud_handler, "is_cloud_ip", return_value=False):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/", headers={"X-Forwarded-For": "8.8.8.8"})
            assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_cloud_ip_refresh() -> None:
    app = FastAPI()
    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        block_cloud_providers={"AWS", "GCP", "Azure"},
        enable_penetration_detection=False,
    )
    middleware = SecurityMiddleware(app, config)

    with patch(
        "guard.handlers.cloud_handler.cloud_handler.is_cloud_ip", return_value=False
    ) as mock_is_cloud_ip:

        async def receive() -> dict[str, str | bytes]:
            return {"type": "http.request", "body": b"test_body"}

        request = Request(
            scope={
                "type": "http",
                "method": "GET",
                "path": "/",
                "headers": [(b"x-forwarded-for", b"192.168.1.1")],
                "client": ("192.168.1.1", 12345),
                "query_string": b"",
                "server": ("testserver", 80),
                "scheme": "http",
            },
            receive=receive,
        )

        body = await request.body()
        assert body == b"test_body"

        async def mock_call_next(request: Request) -> Response:
            return Response("OK")

        response = await middleware.dispatch(request, mock_call_next)

        assert mock_is_cloud_ip.called
        assert isinstance(response, Response)
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_cleanup_rate_limits(security_middleware: SecurityMiddleware) -> None:
    await security_middleware.rate_limit_handler.reset()
    assert isinstance(security_middleware.rate_limit_handler.request_times, TTLCache)
    assert len(security_middleware.rate_limit_handler.request_times) == 0


@pytest.mark.asyncio
async def test_excluded_paths() -> None:
    app = FastAPI()
    config = SecurityConfig(ipinfo_token=IPINFO_TOKEN, exclude_paths=["/health"])
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/health")
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_cloud_ip_blocking_with_refresh() -> None:
    """Test cloud IP blocking with refresh functionality"""
    app = FastAPI()
    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        block_cloud_providers={"AWS", "GCP", "Azure"},
        enable_redis=False,
        enable_penetration_detection=False,
    )

    middleware = SecurityMiddleware(app, config)
    middleware.last_cloud_ip_refresh = int(time.time() - 3700)

    mock_refresh = Mock()
    with (
        patch.object(cloud_handler, "refresh", mock_refresh),
        patch.object(cloud_handler, "is_cloud_ip", return_value=False),
    ):

        async def receive() -> dict[str, str | bytes]:
            return {"type": "http.request", "body": b""}

        request = Request(
            scope={
                "type": "http",
                "method": "GET",
                "path": "/",
                "headers": [(b"x-forwarded-for", b"192.168.1.1")],
                "client": ("192.168.1.1", 12345),
                "query_string": b"",
                "server": ("testserver", 80),
                "scheme": "http",
            },
            receive=receive,
        )

        body = await request.body()
        assert body == b""

        async def mock_call_next(request: Request) -> Response:
            return Response("OK")

        await middleware.dispatch(request, mock_call_next)
        mock_refresh.assert_called_once()

        mock_refresh.reset_mock()
        await middleware.dispatch(request, mock_call_next)
        mock_refresh.assert_not_called()

    # Redis enabled
    config.enable_redis = True
    middleware = SecurityMiddleware(app, config)
    middleware.last_cloud_ip_refresh = int(time.time() - 3700)

    mock_refresh_async = AsyncMock()
    with (
        patch.object(cloud_handler, "refresh_async", mock_refresh_async),
        patch.object(cloud_handler, "is_cloud_ip", return_value=False),
    ):
        await middleware.dispatch(request, mock_call_next)
        mock_refresh_async.assert_awaited_once()


@pytest.mark.asyncio
async def test_refresh_cloud_ips_without_any_cloud() -> None:
    app = FastAPI()
    config = SecurityConfig(ipinfo_token=IPINFO_TOKEN, block_cloud_providers=None)
    middleware = SecurityMiddleware(app, config)
    with (
        patch.object(cloud_handler, "refresh_async") as mock_refresh_async,
        patch.object(cloud_handler, "refresh") as mock_refresh,
    ):
        await middleware.refresh_cloud_ip_ranges()
        mock_refresh_async.assert_not_called()
        mock_refresh.assert_not_called()


@pytest.mark.asyncio
async def test_cors_disabled() -> None:
    """Test CORS configuration when disabled"""
    app = FastAPI()
    config = SecurityConfig(ipinfo_token=IPINFO_TOKEN, enable_cors=False)

    cors_added = SecurityMiddleware.configure_cors(app, config)
    assert not cors_added, "CORS middleware should not be added when disabled"


@pytest.mark.asyncio
async def test_https_enforcement_with_xforwarded_proto() -> None:
    """Test HTTPS enforcement with X-Forwarded-Proto header."""
    app = FastAPI()
    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        enforce_https=True,
        trusted_proxies=["127.0.0.1"],
        trust_x_forwarded_proto=True,
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        # With X-Forwarded-Proto: https, should not redirect
        response = await client.get("/", headers={"X-Forwarded-Proto": "https"})
        assert response.status_code == status.HTTP_200_OK

        # Without X-Forwarded-Proto: https, should redirect to HTTPS
        response = await client.get("/", headers={"X-Forwarded-Proto": "http"})
        assert response.status_code == status.HTTP_301_MOVED_PERMANENTLY
        assert response.headers["location"].startswith("https://")

    # Without trust_x_forwarded_proto, should always redirect
    config.trust_x_forwarded_proto = False
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/", headers={"X-Forwarded-Proto": "https"})
        assert response.status_code == status.HTTP_301_MOVED_PERMANENTLY


@pytest.mark.asyncio
async def test_cleanup_expired_request_times() -> None:
    """Test cleanup of expired request times"""
    app = FastAPI()
    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN, rate_limit=2, rate_limit_window=1
    )
    middleware = SecurityMiddleware(app, config)

    handler = middleware.rate_limit_handler
    handler.request_times.clear()

    handler.request_times["ip1"] = 5
    handler.request_times["ip2"] = 3

    assert "ip1" in handler.request_times
    assert "ip2" in handler.request_times

    # Reset and verify cleared
    await handler.reset()
    assert len(handler.request_times) == 0


@pytest.mark.asyncio
async def test_penetration_detection_disabled() -> None:
    """Test when penetration detection is disabled"""
    app = FastAPI()
    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN, enable_penetration_detection=False
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    @app.get("/wp-admin")
    async def admin_page() -> dict[str, str]:
        return {"message": "Admin"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/wp-admin")
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_cloud_ip_blocking_with_logging() -> None:
    """Test cloud IP blocking with logging functionality"""
    app = FastAPI()
    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        block_cloud_providers={"AWS", "GCP", "Azure"},
        whitelist=[],
        enable_penetration_detection=False,
    )
    middleware = SecurityMiddleware(app, config)
    await middleware.setup_logger()

    call_next_executed = False

    async def mock_call_next(request: Request) -> Response:
        nonlocal call_next_executed
        call_next_executed = True
        return Response("OK")

    with (
        patch.object(cloud_handler, "is_cloud_ip", return_value=True),
        patch("guard.middleware.log_activity") as mock_log,
        patch("guard.middleware.is_ip_allowed", return_value=True),
    ):

        async def receive() -> dict[str, str | bytes]:
            return {"type": "http.request", "body": b""}

        request = Request(
            scope={
                "type": "http",
                "method": "GET",
                "path": "/",
                "headers": [(b"x-forwarded-for", b"13.59.255.255")],
                "client": ("13.59.255.255", 12345),
                "query_string": b"",
                "server": ("testserver", 80),
                "scheme": "http",
            },
            receive=receive,
        )

        body = await request.body()
        assert body == b""

        response = await middleware.dispatch(request, mock_call_next)

        mock_log.assert_any_call(
            request,
            middleware.logger,
            log_type="suspicious",
            reason="Blocked cloud provider IP: 13.59.255.255",
            level="WARNING",
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert not call_next_executed, (
            "call_next should not be executed when IP is blocked"
        )

    with (
        patch.object(cloud_handler, "is_cloud_ip", return_value=False),
        patch("guard.middleware.is_ip_allowed", return_value=True),
    ):

        async def receive2() -> dict[str, str | bytes]:
            return {"type": "http.request", "body": b""}

        request = Request(
            scope={
                "type": "http",
                "method": "GET",
                "path": "/",
                "headers": [(b"x-forwarded-for", b"192.168.1.1")],
                "client": ("192.168.1.1", 12345),
                "query_string": b"",
                "server": ("testserver", 80),
                "scheme": "http",
            },
            receive=receive2,
        )

        body = await request.body()
        assert body == b""

        response = await middleware.dispatch(request, mock_call_next)

        assert call_next_executed, "call_next should be executed for allowed IPs"
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_redis_initialization(security_config_redis: SecurityConfig) -> None:
    """Test Redis initialization in SecurityMiddleware"""
    app = FastAPI()

    security_config_redis.block_cloud_providers = {"AWS"}

    middleware = SecurityMiddleware(app, security_config_redis)

    # Mock external handlers
    with (
        patch.object(middleware.redis_handler, "initialize") as redis_init,
        patch.object(cloud_handler, "initialize_redis") as cloud_init,
        patch.object(ip_ban_manager, "initialize_redis") as ipban_init,
        patch.object(IPInfoManager, "initialize_redis") as ipinfo_init,
        patch.object(sus_patterns_handler, "initialize_redis") as sus_init,
    ):
        await middleware.initialize()

        # Verify Redis handler initialization
        redis_init.assert_awaited_once()

        # Verify component initializations with Redis
        cloud_init.assert_awaited_once_with(middleware.redis_handler, {"AWS"})
        ipban_init.assert_awaited_once_with(middleware.redis_handler)
        ipinfo_init.assert_awaited_once_with(middleware.redis_handler)
        sus_init.assert_awaited_once_with(middleware.redis_handler)


@pytest.mark.asyncio
async def test_redis_initialization_without_ipinfo_and_cloud(
    security_config_redis: SecurityConfig,
) -> None:
    """Test Redis initialization in SecurityMiddleware"""
    app = FastAPI()

    security_config_redis.blocked_countries = []

    middleware = SecurityMiddleware(app, security_config_redis)

    # Mock external handlers
    with (
        patch.object(middleware.redis_handler, "initialize") as redis_init,
        patch.object(cloud_handler, "initialize_redis") as cloud_init,
        patch.object(ip_ban_manager, "initialize_redis") as ipban_init,
        patch.object(IPInfoManager, "initialize_redis") as ipinfo_init,
        patch.object(sus_patterns_handler, "initialize_redis") as sus_init,
    ):
        await middleware.initialize()

        # Verify Redis handler initialization
        redis_init.assert_awaited_once()

        # Verify component initializations with Redis
        cloud_init.assert_not_called()
        ipban_init.assert_awaited_once_with(middleware.redis_handler)
        ipinfo_init.assert_not_called()
        sus_init.assert_awaited_once_with(middleware.redis_handler)


@pytest.mark.asyncio
async def test_redis_disabled(security_config: SecurityConfig) -> None:
    """Test middleware behavior when Redis is disabled"""
    app = FastAPI()
    security_config.enable_redis = False
    middleware = SecurityMiddleware(app, security_config)

    assert middleware.redis_handler is None
    await middleware.initialize()

    assert middleware.rate_limit_handler is not None
    await middleware.rate_limit_handler.reset()


@pytest.mark.asyncio
async def test_request_without_client(security_config: SecurityConfig) -> None:
    """Test handling of request without client info"""
    app = FastAPI()
    middleware = SecurityMiddleware(app, security_config)

    call_next_called = False

    async def mock_call_next(request: Request) -> Response:
        nonlocal call_next_called
        call_next_called = True
        return Response("OK")

    async def receive() -> dict[str, str | bytes]:
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "query_string": b"",
            "server": ("testserver", 80),
            "scheme": "http",
            # No 'client' key here
        },
        receive=receive,
    )

    body = await request.body()
    assert body == b""

    response = await middleware.dispatch(request, mock_call_next)

    assert call_next_called, "call_next should be called when client is None"
    assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_rate_limiting_disabled() -> None:
    """Test when rate limiting is disabled"""
    app = FastAPI()
    config = SecurityConfig(ipinfo_token=IPINFO_TOKEN, enable_rate_limiting=False)
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        for _ in range(10):
            response = await client.get("/")
            assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_rate_limiting_with_redis(security_config_redis: SecurityConfig) -> None:
    """Test rate limiting with Redis"""

    app = FastAPI()
    security_config_redis.rate_limit = 2
    security_config_redis.rate_limit_window = 1

    rate_handler = rate_limit_handler(security_config_redis)
    await rate_handler.reset()

    app.add_middleware(SecurityMiddleware, config=security_config_redis)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        # First request - should be allowed
        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK

        # Second request - should be allowed
        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK

        # Third request - should be rate limited because count > limit
        response = await client.get("/")
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

        # Reset redis keys
        await rate_handler.reset()

        # After reset, should be allowed again
        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_rate_limit_reset_with_redis_errors(
    security_config_redis: SecurityConfig,
) -> None:
    """Test rate limit reset handling Redis errors"""

    security_config_redis.rate_limit = 2
    security_config_redis.enable_rate_limiting = True

    rate_handler = rate_limit_handler(security_config_redis)

    # Mock redis_handler.keys to raise an exception
    async def mock_keys(*args: Any) -> None:
        raise Exception("Redis keys error")

    with (
        patch.object(rate_handler.redis_handler, "keys", mock_keys),
        patch.object(logging.Logger, "error") as mock_logger,
    ):
        await rate_handler.reset()

        # Verify error was logged
        mock_logger.assert_called_once()
        args = mock_logger.call_args[0]
        assert "Failed to reset Redis rate limits" in args[0]


@pytest.mark.asyncio
async def test_passive_mode_penetration_detection() -> None:
    """Test penetration detection in passive mode"""
    app = FastAPI()
    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        passive_mode=True,
        whitelist=[],
    )
    middleware = SecurityMiddleware(app, config)
    await middleware.setup_logger()

    call_next_called = False

    async def mock_call_next(request: Request) -> Response:
        nonlocal call_next_called
        call_next_called = True
        return Response("OK")

    with (
        patch(
            "guard.middleware.detect_penetration_attempt",
            return_value=(True, "SQL injection attempt"),
        ) as mock_detect,
        patch("guard.middleware.log_activity") as mock_log,
    ):

        async def receive() -> dict[str, str | bytes]:
            return {"type": "http.request", "body": b"' OR 1=1; --"}

        request = Request(
            scope={
                "type": "http",
                "method": "GET",
                "path": "/login",
                "headers": [(b"user-agent", b"test-agent")],
                "client": ("192.168.1.1", 12345),
                "query_string": b"",
                "server": ("testserver", 80),
                "scheme": "http",
            },
            receive=receive,
        )

        body = await request.body()
        assert b"' OR 1=1; --" in body

        response = await middleware.dispatch(request, mock_call_next)

        assert response.status_code == status.HTTP_200_OK
        assert call_next_called, "call_next should be called in passive mode"

        mock_detect.assert_called_once_with(request)

        mock_log.assert_any_call(
            request,
            middleware.logger,
            log_type="suspicious",
            reason="Suspicious activity detected: 192.168.1.1",
            passive_mode=True,
            trigger_info="SQL injection attempt",
            level="WARNING",
        )
