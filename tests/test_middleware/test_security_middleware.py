import asyncio
import logging
import os
import time
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport
from redis.exceptions import RedisError

from guard.handlers.cloud_handler import cloud_handler
from guard.handlers.ipinfo_handler import IPInfoManager
from guard.handlers.ratelimit_handler import rate_limit_handler
from guard.handlers.redis_handler import redis_handler
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
        await handler.reset()

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


@pytest.mark.parametrize(
    (
        "test_scenario, expected_status_code, extra_config, "
        "request_path, request_headers, use_custom_check"
    ),
    [
        # NOTE: Normal case
        (
            "normal",
            status.HTTP_200_OK,
            {},
            "/",
            {},
            False,
        ),
        # NOTE: Blacklisted IP
        (
            "blacklisted",
            status.HTTP_403_FORBIDDEN,
            {},
            "/",
            {"X-Forwarded-For": "192.168.1.5"},
            False,
        ),
        # NOTE: HTTPS enforcement
        (
            "https_enforcement",
            status.HTTP_301_MOVED_PERMANENTLY,
            {"enforce_https": True},
            "/",
            {},
            False,
        ),
        # NOTE: Excluded path
        (
            "excluded_path",
            status.HTTP_200_OK,
            {"exclude_paths": ["/excluded"]},
            "/excluded",
            {},
            False,
        ),
        # NOTE: Custom request check
        (
            "custom_request_check",
            status.HTTP_418_IM_A_TEAPOT,
            {},
            "/",
            {"X-Custom-Check": "true"},
            True,
        ),
        # NOTE: Custom request check - no trigger
        (
            "custom_request_check_no_trigger",
            status.HTTP_200_OK,
            {},
            "/",
            {},
            True,
        ),
        # NOTE: Request without client
        (
            "no_client_info",
            status.HTTP_200_OK,
            {},
            "/",
            {},
            False,
        ),
    ],
)
@pytest.mark.asyncio
async def test_custom_response_modifier_parameterized(
    test_scenario: str,
    expected_status_code: int,
    extra_config: dict[str, Any],
    request_path: str,
    request_headers: dict[str, str],
    use_custom_check: bool,
) -> None:
    """
    Parameterized test for the custom response modifier covering all scenarios.
    """
    app = FastAPI()

    async def custom_modifier(response: Response) -> Response:
        response.headers["X-Modified"] = "True"

        if response.status_code >= 400 and not isinstance(response, JSONResponse):
            content = bytes(response.body).decode()

            return JSONResponse(
                status_code=response.status_code,
                content={"detail": content},
                headers={"X-Modified": "True"},
            )

        return response

    async def custom_check(request: Request) -> Response | None:
        if "X-Custom-Check" in request.headers:
            return Response("I'm a teapot", status_code=status.HTTP_418_IM_A_TEAPOT)
        return None

    config_args = {
        "ipinfo_token": IPINFO_TOKEN,
        "blacklist": ["192.168.1.5"],
        "custom_response_modifier": custom_modifier,
        "trusted_proxies": ["127.0.0.1"],
    }

    if use_custom_check:
        config_args["custom_request_check"] = custom_check

    config_args.update(extra_config)
    config = SecurityConfig(**config_args)

    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    @app.get("/excluded")
    async def excluded_path() -> dict[str, str]:
        return {"message": "Excluded Path"}

    if test_scenario == "no_client_info":

        async def receive() -> dict[str, str | bytes]:
            return {"type": "http.request", "body": b""}

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(k.encode(), v.encode()) for k, v in request_headers.items()],
            "query_string": b"",
            "server": ("testserver", 80),
            "scheme": "http",
        }

        request = Request(scope=scope, receive=receive)

        body = await request.body()
        assert body == b""

        middleware = SecurityMiddleware(app, config=config)

        async def call_next(request: Request) -> Response:
            return Response("Test response with no client", status_code=200)

        middleware_response = await middleware.dispatch(request, call_next)

        assert middleware_response.headers.get("X-Modified") == "True"
        assert middleware_response.status_code == expected_status_code

    else:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            httpx_response = await client.get(request_path, headers=request_headers)

            assert httpx_response.headers.get("X-Modified") == "True"

            assert httpx_response.status_code == expected_status_code

            if expected_status_code >= 400:
                response = await client.get(request_path, headers=request_headers)
                response_json = response.json()
                assert "detail" in response_json


@pytest.mark.asyncio
async def test_memoryview_response_handling() -> None:
    """Special test for memoryview response handling"""

    test_body_memoryview = memoryview(b"Test Content")

    test_response_memoryview = Response(test_body_memoryview, status_code=400)
    test_response_normal = Response("Normal", status_code=200)
    test_response_bytes = Response(b"Bytes Content", status_code=400)

    assert isinstance(test_response_memoryview.body, memoryview)

    async def custom_modifier(response: Response) -> Response:
        response.headers["X-Modified"] = "True"

        if response.status_code >= 400 and not isinstance(response, JSONResponse):
            content = bytes(response.body).decode()

            return JSONResponse(
                status_code=response.status_code,
                content={"detail": content},
                headers={"X-Modified": "True"},
            )

        return response

    result_memoryview = await custom_modifier(test_response_memoryview)
    assert isinstance(result_memoryview, JSONResponse)
    assert result_memoryview.status_code == 400
    assert result_memoryview.headers.get("X-Modified") == "True"
    result_json = bytes(result_memoryview.body).decode()
    assert "Test Content" in result_json

    result_bytes = await custom_modifier(test_response_bytes)
    assert isinstance(result_bytes, JSONResponse)
    assert result_bytes.status_code == 400
    assert "Bytes Content" in bytes(result_bytes.body).decode()

    result_normal = await custom_modifier(test_response_normal)
    assert result_normal.status_code == 200
    assert not isinstance(result_normal, JSONResponse)
    assert result_normal.headers.get("X-Modified") == "True"


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
    middleware = SecurityMiddleware(app, config=config)

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
    assert isinstance(security_middleware.rate_limit_handler.request_timestamps, dict)
    assert len(security_middleware.rate_limit_handler.request_timestamps) == 0


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

    middleware = SecurityMiddleware(app, config=config)
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
    middleware = SecurityMiddleware(app, config=config)
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
    middleware = SecurityMiddleware(app, config=config)
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
    middleware = SecurityMiddleware(app, config=config)

    handler = middleware.rate_limit_handler
    await handler.reset()

    assert len(handler.request_timestamps) == 0

    current_time = time.time()
    # Test data
    handler.request_timestamps["ip1"].append(current_time)
    handler.request_timestamps["ip1"].append(current_time)
    handler.request_timestamps["ip2"].append(current_time)

    assert len(handler.request_timestamps["ip1"]) == 2
    assert len(handler.request_timestamps["ip2"]) == 1
    assert len(handler.request_timestamps) == 2

    # Reset and verify cleared
    await handler.reset()
    assert len(handler.request_timestamps) == 0


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
        whitelist=["13.59.255.255"],  # Whitelist so IP security doesn't block it first
        blacklist=[],  # Empty blacklist
        trusted_proxies=["13.59.255.255"],  # Trust the IP as proxy
        enable_penetration_detection=False,
    )
    middleware = SecurityMiddleware(app, config=config)

    call_next_executed = False

    async def mock_call_next(request: Request) -> Response:
        nonlocal call_next_executed
        call_next_executed = True
        return Response("OK")

    with (
        patch.object(cloud_handler, "is_cloud_ip", return_value=True),
        patch(
            "guard.core.checks.implementations.cloud_provider.log_activity"
        ) as mock_log,
        patch(
            "guard.core.checks.implementations.ip_security.is_ip_allowed",
            new_callable=AsyncMock,
            return_value=True,
        ),
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
            passive_mode=False,
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert not call_next_executed, (
            "call_next should not be executed when IP is blocked"
        )

    with (
        patch.object(cloud_handler, "is_cloud_ip", return_value=False),
        patch(
            "guard.core.checks.implementations.ip_security.is_ip_allowed",
            new_callable=AsyncMock,
            return_value=True,
        ),
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

        assert response.status_code == status.HTTP_200_OK
        assert call_next_executed, "call_next should be executed for allowed IPs"


@pytest.mark.asyncio
async def test_redis_initialization(security_config_redis: SecurityConfig) -> None:
    """Test Redis initialization in SecurityMiddleware"""
    app = FastAPI()

    security_config_redis.block_cloud_providers = {"AWS"}

    middleware = SecurityMiddleware(app, config=security_config_redis)

    # Mock external handlers - patch at module level where they're imported
    with (
        patch.object(middleware.redis_handler, "initialize") as redis_init,
        patch(
            "guard.handlers.cloud_handler.cloud_handler.initialize_redis"
        ) as cloud_init,
        patch(
            "guard.handlers.ipban_handler.ip_ban_manager.initialize_redis"
        ) as ipban_init,
        patch.object(IPInfoManager, "initialize_redis") as ipinfo_init,
        patch(
            "guard.handlers.suspatterns_handler.sus_patterns_handler.initialize_redis"
        ) as sus_init,
        patch.object(
            middleware.handler_initializer.rate_limit_handler, "initialize_redis"
        ) as rate_init,
    ):
        await middleware.initialize()

        # Verify Redis handler initialization
        redis_init.assert_awaited_once()

        # Verify component initializations with Redis
        cloud_init.assert_awaited_once_with(middleware.redis_handler, {"AWS"})
        ipban_init.assert_awaited_once_with(middleware.redis_handler)
        ipinfo_init.assert_awaited_once_with(middleware.redis_handler)
        sus_init.assert_awaited_once_with(middleware.redis_handler)
        rate_init.assert_awaited_once_with(middleware.redis_handler)


@pytest.mark.asyncio
async def test_redis_initialization_without_ipinfo_and_cloud(
    security_config_redis: SecurityConfig,
) -> None:
    """Test Redis initialization in SecurityMiddleware"""
    app = FastAPI()

    security_config_redis.blocked_countries = []

    middleware = SecurityMiddleware(app, config=security_config_redis)

    # Mock external handlers - patch at module level where they're imported
    with (
        patch.object(middleware.redis_handler, "initialize") as redis_init,
        patch(
            "guard.handlers.cloud_handler.cloud_handler.initialize_redis"
        ) as cloud_init,
        patch(
            "guard.handlers.ipban_handler.ip_ban_manager.initialize_redis"
        ) as ipban_init,
        patch.object(IPInfoManager, "initialize_redis") as ipinfo_init,
        patch(
            "guard.handlers.suspatterns_handler.sus_patterns_handler.initialize_redis"
        ) as sus_init,
        patch.object(
            middleware.handler_initializer.rate_limit_handler, "initialize_redis"
        ) as rate_init,
    ):
        await middleware.initialize()

        # Verify Redis handler initialization
        redis_init.assert_awaited_once()

        # Verify component initializations with Redis
        cloud_init.assert_not_called()
        ipban_init.assert_awaited_once_with(middleware.redis_handler)
        ipinfo_init.assert_not_called()
        sus_init.assert_awaited_once_with(middleware.redis_handler)
        rate_init.assert_awaited_once_with(middleware.redis_handler)


@pytest.mark.asyncio
async def test_redis_disabled(security_config: SecurityConfig) -> None:
    """Test middleware behavior when Redis is disabled"""
    app = FastAPI()
    security_config.enable_redis = False
    middleware = SecurityMiddleware(app, config=security_config)

    assert middleware.redis_handler is None
    await middleware.initialize()

    assert middleware.rate_limit_handler is not None
    await middleware.rate_limit_handler.reset()


@pytest.mark.asyncio
async def test_request_without_client(security_config: SecurityConfig) -> None:
    """Test handling of request without client info"""
    app = FastAPI()
    middleware = SecurityMiddleware(app, config=security_config)

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
            # NOTE: No 'client' key here
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
        # NOTE: should be allowed
        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK

        # NOTE: should be allowed
        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK

        # NOTE: should be rate limited because count > limit
        response = await client.get("/")
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

        # Reset redis keys
        await rate_handler.reset()

        # NOTE: should be allowed again
        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_rate_limit_reset_with_redis_errors(
    security_config_redis: SecurityConfig,
) -> None:
    """Test rate limit reset handling Redis errors"""

    security_config_redis.rate_limit = 2
    security_config_redis.enable_rate_limiting = True

    handler = redis_handler(security_config_redis)

    rate_handler = rate_limit_handler(security_config_redis)
    await rate_handler.initialize_redis(handler)

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
    middleware = SecurityMiddleware(app, config=config)

    call_next_called = False

    async def mock_call_next(request: Request) -> Response:
        nonlocal call_next_called
        call_next_called = True
        return Response("OK")

    with (
        patch(
            "guard.core.checks.implementations.suspicious_activity.detect_penetration_patterns",
            new_callable=AsyncMock,
            return_value=(True, "SQL injection attempt"),
        ) as mock_detect,
        patch(
            "guard.core.checks.implementations.suspicious_activity.log_activity"
        ) as mock_log,
        patch(
            "guard.utils.detect_penetration_attempt",
            return_value=(True, "SQL injection attempt"),
        ),
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

        # detect_penetration_patterns is called with 4 arguments now
        assert mock_detect.called, "detect_penetration_patterns should be called"

        mock_log.assert_any_call(
            request,
            middleware.logger,
            log_type="suspicious",
            reason="Suspicious activity detected: 192.168.1.1",
            passive_mode=True,
            trigger_info="SQL injection attempt",
            level="WARNING",
        )


@pytest.mark.asyncio
async def test_sliding_window_rate_limiting() -> None:
    """Test that sliding window rate limiting works correctly"""
    app = FastAPI()
    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        rate_limit=3,
        rate_limit_window=1,
        enable_rate_limiting=True,
    )

    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    handler = rate_limit_handler(config)
    await handler.reset()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        # First 3 requests should be allowed
        for _ in range(3):
            response = await client.get("/")
            assert response.status_code == status.HTTP_200_OK

        # 4th request should be rate limited
        response = await client.get("/")
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

        # Wait for window to slide plus a little extra to be safe
        await asyncio.sleep(1.5)

        # After 1.5 seconds, the rate limit should reset
        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_rate_limiter_deque_cleanup(security_config: SecurityConfig) -> None:
    """Test cleanup of old requests from the deque"""
    handler = rate_limit_handler(security_config)
    await handler.reset()

    current_time = time.time()
    window_start = current_time - security_config.rate_limit_window

    client_ip = "192.168.1.1"

    old_queue = handler.request_timestamps[client_ip]
    old_queue.append(window_start - 0.5)
    old_queue.append(window_start - 0.7)
    old_queue.append(window_start - 0.2)

    assert len(old_queue) == 3
    assert all(ts < window_start for ts in old_queue)

    async def receive() -> dict[str, str | bytes]:
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "client": (client_ip, 12345),
            "query_string": b"",
            "server": ("testserver", 80),
            "scheme": "http",
        },
        receive=receive,
    )

    body = await request.body()
    assert body == b""

    async def create_error_response(status_code: int, message: str) -> Response:
        return Response(message, status_code=status_code)

    response = await create_error_response(429, "Test message")
    assert response.status_code == 429
    assert response.body == b"Test message"

    result = await handler.check_rate_limit(request, client_ip, create_error_response)

    assert result is None

    assert len(handler.request_timestamps[client_ip]) == 1

    handler.request_timestamps[client_ip].clear()
    handler.request_timestamps[client_ip].append(window_start - 10)  # Way before window
    handler.request_timestamps[client_ip].append(window_start + 0.5)  # Within window

    result = await handler.check_rate_limit(request, client_ip, create_error_response)

    assert result is None

    assert len(handler.request_timestamps[client_ip]) == 2
    assert all(ts >= window_start for ts in handler.request_timestamps[client_ip])


@pytest.mark.asyncio
async def test_lua_script_execution(security_config_redis: SecurityConfig) -> None:
    """Test that the Lua script is executed properly for rate limiting with Redis"""
    app = FastAPI()
    config = security_config_redis
    config.rate_limit = 2
    config.rate_limit_window = 1
    config.enable_rate_limiting = True

    middleware = SecurityMiddleware(app, config=config)
    handler = middleware.rate_limit_handler

    with patch.object(handler.redis_handler, "get_connection") as mock_get_connection:
        mock_conn = AsyncMock()
        mock_conn.evalsha = AsyncMock(return_value=1)

        mock_context = AsyncMock()
        mock_context.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_context.__aexit__ = AsyncMock()
        mock_get_connection.return_value = mock_context

        handler.rate_limit_script_sha = "test_script_sha"

        async def receive() -> dict[str, str | bytes]:
            return {"type": "http.request", "body": b""}

        request = Request(
            scope={
                "type": "http",
                "method": "GET",
                "path": "/",
                "headers": [],
                "client": ("192.168.1.1", 12345),
                "query_string": b"",
                "server": ("testserver", 80),
                "scheme": "http",
            },
            receive=receive,
        )

        body = await request.body()
        assert body == b""

        async def create_error_response(status_code: int, message: str) -> Response:
            return Response(message, status_code=status_code)

        result = await handler.check_rate_limit(
            request, "192.168.1.1", create_error_response
        )
        assert result is None  # NOTE: should not be rate limited

        mock_conn.evalsha.assert_called_once()

        mock_conn.evalsha.reset_mock()
        mock_conn.evalsha.return_value = 3  # NOTE: over the limit

        result = await handler.check_rate_limit(
            request, "192.168.1.1", create_error_response
        )
        assert result is not None
        assert result.status_code == status.HTTP_429_TOO_MANY_REQUESTS


@pytest.mark.asyncio
async def test_fallback_to_pipeline(security_config_redis: SecurityConfig) -> None:
    """Test fallback to pipeline if Lua script fails"""
    app = FastAPI()
    config = security_config_redis
    config.rate_limit = 2
    config.rate_limit_window = 1
    config.enable_rate_limiting = True

    middleware = SecurityMiddleware(app, config=config)
    handler = middleware.rate_limit_handler

    with patch.object(handler.redis_handler, "get_connection") as mock_get_connection:
        mock_conn = AsyncMock()

        mock_pipeline = Mock()
        mock_pipeline.zadd = Mock()
        mock_pipeline.zremrangebyscore = Mock()
        mock_pipeline.zcard = Mock()
        mock_pipeline.expire = Mock()

        mock_pipeline.execute = AsyncMock(
            side_effect=[
                [0, 0, 1, True],  # NOTE: zadd, zrem, zcard (1), expire results
                [0, 0, 3, True],  # NOTE: zadd, zrem, zcard (3), expire results
            ]
        )

        mock_conn.pipeline = Mock(return_value=mock_pipeline)

        mock_context = AsyncMock()
        mock_context.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_context.__aexit__ = AsyncMock()
        mock_get_connection.return_value = mock_context

        handler.rate_limit_script_sha = None

        async def receive() -> dict[str, str | bytes]:
            return {"type": "http.request", "body": b""}

        request = Request(
            scope={
                "type": "http",
                "method": "GET",
                "path": "/",
                "headers": [],
                "client": ("192.168.1.1", 12345),
                "query_string": b"",
                "server": ("testserver", 80),
                "scheme": "http",
            },
            receive=receive,
        )

        body = await request.body()
        assert body == b""

        async def create_error_response(status_code: int, message: str) -> Response:
            return Response(message, status_code=status_code)

        result = await handler.check_rate_limit(
            request, "192.168.1.1", create_error_response
        )
        assert result is None  # NOTE: should not be rate limited

        mock_conn.pipeline.assert_called_once()
        mock_pipeline.zadd.assert_called_once()
        mock_pipeline.zremrangebyscore.assert_called_once()
        mock_pipeline.zcard.assert_called_once()
        mock_pipeline.expire.assert_called_once()
        mock_pipeline.execute.assert_called_once()

        mock_conn.pipeline.reset_mock()
        mock_pipeline.zadd.reset_mock()
        mock_pipeline.zremrangebyscore.reset_mock()
        mock_pipeline.zcard.reset_mock()
        mock_pipeline.expire.reset_mock()
        mock_pipeline.execute.reset_mock()

        result = await handler.check_rate_limit(
            request, "192.168.1.1", create_error_response
        )
        assert result is not None
        assert result.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert result.body == b"Too many requests"

        mock_conn.pipeline.assert_called_once()
        mock_pipeline.zadd.assert_called_once()
        mock_pipeline.zremrangebyscore.assert_called_once()
        mock_pipeline.zcard.assert_called_once()
        mock_pipeline.expire.assert_called_once()
        mock_pipeline.execute.assert_called_once()


@pytest.mark.asyncio
async def test_rate_limiter_redis_errors(security_config_redis: SecurityConfig) -> None:
    """Test Redis error handling in rate limit check"""
    app = FastAPI()
    config = security_config_redis
    config.rate_limit = 2
    config.rate_limit_window = 1
    config.enable_rate_limiting = True

    middleware = SecurityMiddleware(app, config=config)
    handler = middleware.rate_limit_handler

    async def receive() -> dict[str, str | bytes]:
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "client": ("192.168.1.1", 12345),
            "query_string": b"",
            "server": ("testserver", 80),
            "scheme": "http",
        },
        receive=receive,
    )

    body = await request.body()
    assert body == b""

    async def create_error_response(status_code: int, message: str) -> Response:
        return Response(message, status_code=status_code)

    error_response = await create_error_response(429, "Rate limited")
    assert error_response.status_code == 429
    assert error_response.body == b"Rate limited"

    with (
        patch.object(handler.redis_handler, "get_connection") as mock_get_connection,
        patch.object(logging.Logger, "error") as mock_error,
        patch.object(logging.Logger, "info") as mock_info,
    ):
        mock_conn = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(
            side_effect=RedisError("Redis connection error")
        )
        mock_get_connection.return_value = mock_conn

        handler.rate_limit_script_sha = "test_script_sha"

        result = await handler.check_rate_limit(
            request, "192.168.1.1", create_error_response
        )

        assert result is None

        mock_error.assert_called_once()
        assert "Redis rate limiting error" in mock_error.call_args[0][0]
        mock_info.assert_called_once_with("Falling back to in-memory rate limiting")

    with (
        patch.object(handler.redis_handler, "get_connection") as mock_get_connection,
        patch.object(logging.Logger, "error") as mock_error,
    ):
        mock_conn = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(side_effect=Exception("Unexpected error"))
        mock_get_connection.return_value = mock_conn

        result = await handler.check_rate_limit(
            request, "192.168.1.1", create_error_response
        )

        assert result is None

        mock_error.assert_called_once()
        assert "Unexpected error in rate limiting" in mock_error.call_args[0][0]


@pytest.mark.asyncio
async def test_rate_limiter_init_redis_exception(
    security_config_redis: SecurityConfig,
) -> None:
    """Test exception handling during Redis script loading"""
    handler = rate_limit_handler(security_config_redis)

    mock_redis = Mock()
    mock_cm = AsyncMock()
    mock_conn = AsyncMock()
    mock_conn.script_load = AsyncMock(side_effect=Exception("Script load failed"))
    mock_cm.__aenter__.return_value = mock_conn
    mock_redis.get_connection.return_value = mock_cm

    mock_logger = Mock()
    handler.logger = mock_logger

    await handler.initialize_redis(mock_redis)

    mock_logger.error.assert_called_once()
    error_msg = mock_logger.error.call_args[0][0]
    assert "Failed to load rate limiting Lua script: Script load failed" == error_msg


@pytest.mark.asyncio
async def test_ipv6_rate_limiting(
    security_config_redis: SecurityConfig, clean_rate_limiter: None
) -> None:
    """
    Test the rate limiting functionality
    of the SecurityMiddleware with IPv6 addresses.
    """
    app = FastAPI()
    config = security_config_redis
    config.rate_limit = 2
    config.rate_limit_window = 1
    config.enable_rate_limiting = True
    config.trusted_proxies = ["127.0.0.1"]
    config.whitelist = []
    config.enable_penetration_detection = False

    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/", headers={"X-Forwarded-For": "2001:db8::1"})
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/", headers={"X-Forwarded-For": "2001:db8::1"})
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/", headers={"X-Forwarded-For": "2001:db8::1"})
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

        handler = rate_limit_handler(config)
        await handler.reset()

        response = await client.get("/", headers={"X-Forwarded-For": "2001:db8::1"})
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_ipv6_whitelist_blacklist(security_config_redis: SecurityConfig) -> None:
    """
    Test the IPv6 whitelist/blacklist
    functionality of the SecurityMiddleware.
    """
    app = FastAPI()
    config = security_config_redis
    config.whitelist = ["::1", "2001:db8::1"]
    config.blacklist = ["2001:db8::dead:beef"]
    config.enable_penetration_detection = False
    config.trusted_proxies = ["127.0.0.1", "::1"]

    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        # IPv6 loopback
        response = await client.get("/", headers={"X-Forwarded-For": "::1"})
        assert response.status_code == status.HTTP_200_OK

        # Whitelisted IPv6 address
        response = await client.get("/", headers={"X-Forwarded-For": "2001:db8::1"})
        assert response.status_code == status.HTTP_200_OK

        # Blacklisted IPv6 address
        response = await client.get(
            "/", headers={"X-Forwarded-For": "2001:db8::dead:beef"}
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

        # Non-whitelisted IPv6 address (block)
        response = await client.get("/", headers={"X-Forwarded-For": "2001:db8::2"})
        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_ipv6_cidr_whitelist_blacklist(
    security_config_redis: SecurityConfig,
) -> None:
    """
    Test IPv6 CIDR notation in whitelist/blacklist.
    """
    app = FastAPI()
    config = security_config_redis
    config.whitelist = ["2001:db8::/32"]
    config.blacklist = ["2001:db8:dead::/48"]
    config.enable_penetration_detection = False
    config.trusted_proxies = ["127.0.0.1", "::1"]

    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        # IPv6 address in whitelisted CIDR
        response = await client.get("/", headers={"X-Forwarded-For": "2001:db8::1"})
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/", headers={"X-Forwarded-For": "2001:db8:1::1"})
        assert response.status_code == status.HTTP_200_OK

        # IPv6 address in blacklisted CIDR (blacklist overrides whitelist)
        response = await client.get(
            "/", headers={"X-Forwarded-For": "2001:db8:dead::beef"}
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

        # IPv6 address outside whitelisted CIDR
        response = await client.get("/", headers={"X-Forwarded-For": "2001:db9::1"})
        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_mixed_ipv4_ipv6_handling(security_config_redis: SecurityConfig) -> None:
    """
    Test handling of mixed IPv4 and IPv6 addresses in configuration.
    """
    app = FastAPI()
    config = security_config_redis
    config.whitelist = ["127.0.0.1", "::1", "192.168.1.0/24", "2001:db8::/32"]
    config.blacklist = ["192.168.1.100", "2001:db8:dead::beef"]
    config.enable_penetration_detection = False
    config.trusted_proxies = ["127.0.0.1", "::1"]

    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        # IPv4 addresses
        response = await client.get("/", headers={"X-Forwarded-For": "127.0.0.1"})
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.50"})
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.100"})
        assert response.status_code == status.HTTP_403_FORBIDDEN

        # IPv6 addresses
        response = await client.get("/", headers={"X-Forwarded-For": "::1"})
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/", headers={"X-Forwarded-For": "2001:db8::1"})
        assert response.status_code == status.HTTP_200_OK

        response = await client.get(
            "/", headers={"X-Forwarded-For": "2001:db8:dead::beef"}
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_real_ipv6_connection(
    security_config_redis: SecurityConfig, clean_rate_limiter: None
) -> None:
    """
    Test with a real IPv6 client connection using direct Request objects.
    This validates that the middleware can handle actual IPv6 client IPs,
    not just IPv6 addresses in proxy headers.
    """
    config = security_config_redis
    config.rate_limit = 3
    config.rate_limit_window = 2
    config.enable_rate_limiting = True
    config.whitelist = ["2001:db8::1"]
    config.enable_penetration_detection = False

    middleware = SecurityMiddleware(app=Mock(), config=config)

    async def mock_call_next(request: Request) -> Response:
        return Response("OK", status_code=200)

    async def receive() -> dict[str, str | bytes | bool]:
        return {"type": "http.request", "body": b"", "more_body": False}

    # IPv6 client (whitelisted)
    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "query_string": b"",
            "client": ("2001:db8::1", 12345),
            "server": ("testserver", 80),
            "scheme": "http",
        },
        receive=receive,
    )

    response = await middleware.dispatch(request, mock_call_next)
    assert response.status_code == 200

    response = await middleware.dispatch(request, mock_call_next)
    assert response.status_code == 200

    response = await middleware.dispatch(request, mock_call_next)
    assert response.status_code == 200

    response = await middleware.dispatch(request, mock_call_next)
    assert response.status_code == 429

    # Blocked IPv6 client
    request_blocked = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "query_string": b"",
            "client": ("2001:db8::2", 12345),  # NOTE: Different IPv6 client
            "server": ("testserver", 80),
            "scheme": "http",
        },
        receive=receive,
    )

    body = await request.body()
    assert body == b""

    response = await middleware.dispatch(request_blocked, mock_call_next)
    assert response.status_code == 403


async def test_emergency_mode_passive(security_config: SecurityConfig) -> None:
    """Test emergency mode in passive mode."""
    app = FastAPI()
    security_config.emergency_mode = True
    security_config.passive_mode = True
    security_config.trusted_proxies = ["127.0.0.1"]

    @app.get("/test")
    async def test_endpoint() -> dict[str, str]:
        return {"message": "ok"}

    app.add_middleware(SecurityMiddleware, config=security_config)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Should pass in passive mode
        response = await client.get("/test", headers={"X-Forwarded-For": "8.8.8.8"})
        assert response.status_code == 200
