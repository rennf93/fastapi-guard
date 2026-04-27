import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from guard import SecurityConfig
from guard.middleware import SecurityMiddleware


@pytest.fixture
def cors_app() -> FastAPI:
    app = FastAPI()
    config = SecurityConfig(
        enable_cors=True,
        cors_allow_origins=["https://app.example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["X-Custom"],
        cors_allow_credentials=True,
        cors_max_age=600,
        blacklist=["10.0.0.99"],
        trusted_proxies=["127.0.0.1"],
        enable_redis=False,
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def root() -> dict[str, str]:
        return {"ok": "yes"}

    return app


@pytest.mark.asyncio
async def test_preflight_allowed_for_legitimate_origin(cors_app: FastAPI) -> None:
    async with AsyncClient(
        transport=ASGITransport(app=cors_app), base_url="http://test"
    ) as client:
        response = await client.options(
            "/",
            headers={
                "Origin": "https://app.example.com",
                "Access-Control-Request-Method": "POST",
                "X-Forwarded-For": "1.2.3.4",
            },
        )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://app.example.com"


@pytest.mark.asyncio
async def test_preflight_blocked_for_banned_ip(cors_app: FastAPI) -> None:
    async with AsyncClient(
        transport=ASGITransport(app=cors_app), base_url="http://test"
    ) as client:
        response = await client.options(
            "/",
            headers={
                "Origin": "https://app.example.com",
                "Access-Control-Request-Method": "POST",
                "X-Forwarded-For": "10.0.0.99",
            },
        )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_normal_request_carries_cors_headers_when_origin_allowed(
    cors_app: FastAPI,
) -> None:
    async with AsyncClient(
        transport=ASGITransport(app=cors_app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/",
            headers={
                "Origin": "https://app.example.com",
                "X-Forwarded-For": "1.2.3.4",
            },
        )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://app.example.com"
    assert response.headers["access-control-allow-credentials"] == "true"


def test_no_configure_cors_static_method() -> None:
    assert not hasattr(SecurityMiddleware, "configure_cors")


@pytest.fixture
def cors_app_with_passthrough() -> FastAPI:
    app = FastAPI()
    config = SecurityConfig(
        enable_cors=True,
        cors_allow_origins=["https://app.example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["X-Custom"],
        cors_allow_credentials=True,
        cors_max_age=600,
        exclude_paths=["/health"],
        trusted_proxies=["127.0.0.1"],
        enable_redis=False,
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


@pytest.mark.asyncio
async def test_preflight_to_passthrough_path_returns_cors_response(
    cors_app_with_passthrough: FastAPI,
) -> None:
    async with AsyncClient(
        transport=ASGITransport(app=cors_app_with_passthrough), base_url="http://test"
    ) as client:
        response = await client.options(
            "/health",
            headers={
                "Origin": "https://app.example.com",
                "Access-Control-Request-Method": "GET",
            },
        )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://app.example.com"


@pytest.mark.asyncio
async def test_normal_request_to_passthrough_path_carries_cors_headers(
    cors_app_with_passthrough: FastAPI,
) -> None:
    async with AsyncClient(
        transport=ASGITransport(app=cors_app_with_passthrough), base_url="http://test"
    ) as client:
        response = await client.get(
            "/health",
            headers={"Origin": "https://app.example.com"},
        )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://app.example.com"
    assert response.headers["access-control-allow-credentials"] == "true"
