import asyncio
import os
import time
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import FastAPI, Request, Response, status
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport

from guard.handlers.cloud_handler import cloud_handler
from guard.handlers.ipban_handler import ip_ban_manager
from guard.handlers.ipinfo_handler import IPInfoManager
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig
from guard.sus_patterns import SusPatterns

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

        await asyncio.sleep(1)

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
        ipinfo_token=IPINFO_TOKEN, whitelist=["127.0.0.1"], blacklist=["192.168.1.1"]
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
    config1 = SecurityConfig(ipinfo_token=IPINFO_TOKEN, blocked_user_agents=[r"badbot"])
    config2 = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN, whitelist=["127.0.0.1"], blacklist=["192.168.1.1"]
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
        ipinfo_token=IPINFO_TOKEN, block_cloud_providers={"AWS", "GCP", "Azure"}
    )
    middleware = SecurityMiddleware(app, config)

    with patch(
        "guard.handlers.cloud_handler.CloudManager.is_cloud_ip", return_value=False
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
    security_middleware.request_times.update(
        {"expired_ip": [time.time() - 200], "fresh_ip": [time.time() - 30]}
    )

    await security_middleware.cleanup_rate_limits()

    assert len(security_middleware.request_times["fresh_ip"]) == 1
    assert len(security_middleware.request_times["expired_ip"]) == 1


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
async def test_cors_disabled() -> None:
    """Test CORS configuration when disabled"""
    app = FastAPI()
    config = SecurityConfig(ipinfo_token=IPINFO_TOKEN, enable_cors=False)

    cors_added = SecurityMiddleware.configure_cors(app, config)
    assert not cors_added, "CORS middleware should not be added when disabled"


@pytest.mark.asyncio
async def test_https_enforcement() -> None:
    """Test HTTPS enforcement functionality"""
    app = FastAPI()
    config = SecurityConfig(ipinfo_token=IPINFO_TOKEN, enforce_https=True)
    app.add_middleware(SecurityMiddleware, config=config)

    handler_called = False

    @app.get("/")
    async def read_root() -> dict[str, str]:
        nonlocal handler_called
        handler_called = True
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")
        assert response.status_code == status.HTTP_301_MOVED_PERMANENTLY
        assert response.headers["location"].startswith("https://")
        assert not handler_called, (
            "Handler should not be called for redirected requests"
        )

    config.enforce_https = False
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK
        assert handler_called, "Handler should be called for non-redirected requests"


@pytest.mark.asyncio
async def test_cleanup_expired_request_times() -> None:
    """Test cleanup of expired request times"""
    app = FastAPI()
    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN, rate_limit=2, rate_limit_window=1
    )
    middleware = SecurityMiddleware(app, config)

    middleware.last_cleanup = 0

    current_time = time.time()
    old_time = current_time - 120

    middleware.request_times = {
        "ip1": [old_time, old_time],
        "ip2": [current_time],
        "ip3": [old_time, current_time],
    }

    await middleware.cleanup_rate_limits()

    assert "ip1" not in middleware.request_times
    assert len(middleware.request_times["ip2"]) == 1
    assert len(middleware.request_times["ip3"]) == 1
    assert middleware.request_times["ip3"][0] == current_time


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
        patch("guard.middleware.log_suspicious_activity") as mock_log,
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

        mock_log.assert_called_once_with(
            request, "Blocked cloud provider IP: 13.59.255.255", middleware.logger
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
    middleware = SecurityMiddleware(app, security_config_redis)

    # Mock external handlers
    with (
        patch.object(middleware.redis_handler, "initialize") as redis_init,
        patch.object(cloud_handler, "initialize_redis") as cloud_init,
        patch.object(ip_ban_manager, "initialize_redis") as ipban_init,
        patch.object(IPInfoManager, "initialize_redis") as ipinfo_init,
        patch.object(SusPatterns(), "initialize_redis") as sus_init,
        patch.object(
            cloud_handler, "refresh_async", new_callable=AsyncMock
        ) as cloud_refresh,
    ):
        await middleware.initialize()

        # Verify Redis handler initialization
        redis_init.assert_awaited_once()

        # Verify component initializations with Redis
        cloud_init.assert_awaited_once_with(middleware.redis_handler)
        ipban_init.assert_awaited_once_with(middleware.redis_handler)
        ipinfo_init.assert_awaited_once_with(middleware.redis_handler)
        sus_init.assert_awaited_once_with(middleware.redis_handler)
        # Verify initial cloud refresh
        cloud_refresh.assert_awaited_once()


@pytest.mark.asyncio
async def test_redis_disabled(security_config: SecurityConfig) -> None:
    """Test middleware behavior when Redis is disabled"""
    app = FastAPI()
    security_config.enable_redis = False
    middleware = SecurityMiddleware(app, security_config)

    assert middleware.redis_handler is None

    await middleware.initialize()
    await middleware.cleanup_rate_limits()


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
