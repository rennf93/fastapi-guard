import asyncio
from fastapi import FastAPI, Request, Response, status
from guard.cloud_ips import cloud_ip_ranges
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport
import pytest
import time
from unittest.mock import patch


@pytest.mark.asyncio
async def test_rate_limiting():
    """
    Test the rate limiting functionality
    of the SecurityMiddleware.
    """
    app = FastAPI()
    config = SecurityConfig()
    app.add_middleware(
        SecurityMiddleware, config=config, rate_limit=2, rate_limit_window=1
    )

    @app.get("/")
    async def read_root():
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
async def test_ip_whitelist_blacklist():
    """
    Test the IP whitelist/blacklist
    functionality of the SecurityMiddleware.
    """
    app = FastAPI()
    config = SecurityConfig(whitelist=["127.0.0.1"], blacklist=["192.168.1.1"])
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root():
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
async def test_user_agent_filtering():
    """
    Test the user agent filtering
    functionality of the SecurityMiddleware.
    """
    app = FastAPI()
    config = SecurityConfig(blocked_user_agents=[r"badbot"])
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root():
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/", headers={"User-Agent": "goodbot"})
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/", headers={"User-Agent": "badbot"})
        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_rate_limiting_multiple_ips(reset_state, security_middleware):
    """
    Test the rate limiting functionality
    of the SecurityMiddleware with multiple IPs.
    """
    app = FastAPI()
    config = SecurityConfig(whitelist=[], blacklist=[])
    app.add_middleware(
        SecurityMiddleware, config=config, rate_limit=2, rate_limit_window=1
    )

    @app.get("/")
    async def read_root():
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        # IP 1
        for i in range(1, 4):
            response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.1"})
            assert response.status_code == (
                status.HTTP_200_OK if i <= 2 else status.HTTP_429_TOO_MANY_REQUESTS
            )

        # IP 2
        for i in range(1, 4):
            response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.5"})
            assert response.status_code == (
                status.HTTP_200_OK if i <= 2 else status.HTTP_429_TOO_MANY_REQUESTS
            )

        # Ensure IP 1 is still rate limited
        response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.1"})
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

        # Ensure IP 2 is still rate limited
        response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.5"})
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS


@pytest.mark.asyncio
async def test_middleware_multiple_configs():
    """
    Test the SecurityMiddleware
    with multiple configurations.
    """
    app = FastAPI()
    config1 = SecurityConfig(blocked_user_agents=[r"badbot"])
    config2 = SecurityConfig(whitelist=["127.0.0.1"], blacklist=["192.168.1.1"])

    app.add_middleware(SecurityMiddleware, config=config1)
    app.add_middleware(SecurityMiddleware, config=config2)

    @app.get("/")
    async def read_root():
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Test user agent filtering
        response = await client.get("/", headers={"User-Agent": "badbot"})
        assert response.status_code == status.HTTP_403_FORBIDDEN

        # Test IP whitelist/blacklist
        response = await client.get("/", headers={"X-Forwarded-For": "127.0.0.1"})
        assert response.status_code == status.HTTP_200_OK
        response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.1"})
        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_https_enforcement():
    """
    Test the HTTPS enforcement
    functionality of the SecurityMiddleware.
    """
    app = FastAPI()
    config = SecurityConfig(enforce_https=True)
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root():
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")
        assert response.status_code == status.HTTP_301_MOVED_PERMANENTLY
        assert response.headers["location"].startswith("https://")

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="https://test"
    ) as client:
        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_custom_request_check():
    """
    Test the custom request check
    functionality of the SecurityMiddleware.
    """
    app = FastAPI()

    async def custom_check(request: Request):
        if request.headers.get("X-Custom-Header") == "block":
            return Response("Custom block", status_code=status.HTTP_403_FORBIDDEN)
        return None

    config = SecurityConfig(custom_request_check=custom_check)
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root():
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
async def test_custom_error_responses():
    """
    Test the custom error responses.
    """
    app = FastAPI()
    config = SecurityConfig(
        blacklist=["192.168.1.3"],
        custom_error_responses={
            403: "Custom Forbidden",
            429: "Custom Too Many Requests",
        },
        rate_limit=5,
        auto_ban_threshold=10,
    )
    app.add_middleware(
        SecurityMiddleware, config=config, rate_limit=5, rate_limit_window=1
    )

    @app.get("/")
    async def read_root():
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Test blacklisted IP
        response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.3"})
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.text == "Custom Forbidden"

        # Test rate limiting
        for _ in range(5):
            response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.4"})
            assert response.status_code == status.HTTP_200_OK

        response = await client.get("/", headers={"X-Forwarded-For": "192.168.1.4"})
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert response.text == "Custom Too Many Requests"


@pytest.mark.asyncio
async def test_cors_configuration():
    app = FastAPI()
    config = SecurityConfig(
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

    if "access-control-expose-headers" in response.headers:
        assert "X-Custom-Header" in response.headers["access-control-expose-headers"]
    else:
        print("Warning: access-control-expose-headers not present in response")

    assert response.headers["access-control-max-age"] == "600"


@pytest.mark.asyncio
async def test_cloud_ip_blocking():
    app = FastAPI()
    config = SecurityConfig(block_cloud_providers={"AWS", "GCP", "Azure"})
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root():
        return {"message": "Hello World"}

    with patch.object(cloud_ip_ranges, "is_cloud_ip", return_value=True):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get(
                "/", headers={"X-Forwarded-For": "13.59.255.255"}
            )
            assert response.status_code == status.HTTP_403_FORBIDDEN

    with patch.object(cloud_ip_ranges, "is_cloud_ip", return_value=False):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/", headers={"X-Forwarded-For": "8.8.8.8"})
            assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_cloud_ip_refresh():
    app = FastAPI()
    config = SecurityConfig(block_cloud_providers={"AWS", "GCP", "Azure"})
    middleware = SecurityMiddleware(app, config)

    # Set the initial last_cloud_ip_refresh to a time more than 24 hours ago
    initial_refresh_time = time.time() - 86401
    middleware.last_cloud_ip_refresh = initial_refresh_time

    with patch.object(cloud_ip_ranges, "refresh") as mock_refresh, patch.object(
        cloud_ip_ranges, "is_cloud_ip", return_value=False
    ) as mock_is_cloud_ip:

        async def receive():
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
            }
        )
        request._receive = receive

        async def mock_call_next(request):
            return Response("OK")

        response = await middleware.dispatch(request, mock_call_next)

        # Assertions
        mock_refresh.assert_called_once()
        mock_is_cloud_ip.assert_called_once_with("192.168.1.1", {"AWS", "GCP", "Azure"})
        assert middleware.last_cloud_ip_refresh > initial_refresh_time
        assert middleware.last_cloud_ip_refresh <= time.time()
        assert isinstance(response, Response)
        assert response.status_code == 200
        assert response.body == b"OK"

    # Verify that a second request within 24 hours doesn't trigger another refresh
    with patch.object(cloud_ip_ranges, "refresh") as mock_refresh:
        await middleware.dispatch(request, mock_call_next)
        mock_refresh.assert_not_called()
