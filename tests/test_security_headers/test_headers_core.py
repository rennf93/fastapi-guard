from collections.abc import AsyncGenerator
from typing import Any

import pytest
from fastapi import FastAPI, Response
from fastapi.testclient import TestClient

from guard.handlers.security_headers_handler import (
    SecurityHeadersManager,
    security_headers_manager,
)
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig


@pytest.fixture
async def reset_headers_manager() -> AsyncGenerator[None, None]:
    """Reset security headers manager state before each test."""
    await security_headers_manager.reset()
    yield
    await security_headers_manager.reset()


def test_default_security_headers(reset_headers_manager: None) -> None:
    """Test that default security headers are applied."""
    app = FastAPI()
    config = SecurityConfig(
        security_headers={"enabled": True},
        enable_redis=False,
        enable_agent=False,
        passive_mode=True,
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/test")
    async def test_endpoint() -> dict[str, str]:
        return {"message": "test"}

    client = TestClient(app)
    response = client.get("/test")

    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "SAMEORIGIN"
    assert response.headers["X-XSS-Protection"] == "1; mode=block"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "Permissions-Policy" in response.headers


def test_custom_csp_header(reset_headers_manager: None) -> None:
    """Test Content Security Policy header configuration."""
    app = FastAPI()
    config = SecurityConfig(
        security_headers={
            "enabled": True,
            "csp": {
                "default-src": ["'self'"],
                "script-src": ["'self'", "https://trusted.cdn.com"],
                "style-src": ["'self'", "'unsafe-inline'"],
            },
        },
        enable_redis=False,
        enable_agent=False,
        passive_mode=True,
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/test")
    async def test_endpoint() -> dict[str, str]:
        return {"message": "test"}

    client = TestClient(app)
    response = client.get("/test")

    assert response.status_code == 200
    csp = response.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "script-src 'self' https://trusted.cdn.com" in csp
    assert "style-src 'self' 'unsafe-inline'" in csp


def test_hsts_header(reset_headers_manager: None) -> None:
    """Test HTTP Strict Transport Security header."""
    app = FastAPI()
    config = SecurityConfig(
        security_headers={
            "enabled": True,
            "hsts": {
                "max_age": 31536000,
                "include_subdomains": True,
                "preload": True,
            },
        },
        enable_redis=False,
        enable_agent=False,
        passive_mode=True,
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/test")
    async def test_endpoint() -> dict[str, str]:
        return {"message": "test"}

    client = TestClient(app)
    response = client.get("/test")

    assert response.status_code == 200
    hsts = response.headers["Strict-Transport-Security"]
    assert "max-age=31536000" in hsts
    assert "includeSubDomains" in hsts
    assert "preload" in hsts


def test_custom_headers(reset_headers_manager: None) -> None:
    """Test custom security headers."""
    app = FastAPI()
    config = SecurityConfig(
        security_headers={
            "enabled": True,
            "custom": {
                "X-Custom-Header": "custom-value",
                "X-Another-Header": "another-value",
            },
        },
        enable_redis=False,
        enable_agent=False,
        passive_mode=True,
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/test")
    async def test_endpoint() -> dict[str, str]:
        return {"message": "test"}

    client = TestClient(app)
    response = client.get("/test")

    assert response.status_code == 200
    assert response.headers["X-Custom-Header"] == "custom-value"
    assert response.headers["X-Another-Header"] == "another-value"


def test_frame_options_deny(reset_headers_manager: None) -> None:
    """Test X-Frame-Options with DENY value."""
    app = FastAPI()
    config = SecurityConfig(
        security_headers={
            "enabled": True,
            "frame_options": "DENY",
        },
        enable_redis=False,
        enable_agent=False,
        passive_mode=True,
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/test")
    async def test_endpoint() -> dict[str, str]:
        return {"message": "test"}

    client = TestClient(app)
    response = client.get("/test")

    assert response.status_code == 200
    assert response.headers["X-Frame-Options"] == "DENY"


def test_custom_referrer_policy(reset_headers_manager: None) -> None:
    """Test custom Referrer-Policy header."""
    app = FastAPI()
    config = SecurityConfig(
        security_headers={
            "enabled": True,
            "referrer_policy": "no-referrer",
        },
        enable_redis=False,
        enable_agent=False,
        passive_mode=True,
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/test")
    async def test_endpoint() -> dict[str, str]:
        return {"message": "test"}

    client = TestClient(app)
    response = client.get("/test")

    assert response.status_code == 200
    assert response.headers["Referrer-Policy"] == "no-referrer"


def test_permissions_policy_disabled(reset_headers_manager: None) -> None:
    """Test disabling Permissions-Policy header."""
    app = FastAPI()
    config = SecurityConfig(
        security_headers={
            "enabled": True,
            "permissions_policy": None,
        },
        enable_redis=False,
        enable_agent=False,
        passive_mode=True,
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/test")
    async def test_endpoint() -> dict[str, str]:
        return {"message": "test"}

    client = TestClient(app)
    response = client.get("/test")

    assert response.status_code == 200
    assert "Permissions-Policy" not in response.headers


def test_security_headers_disabled(reset_headers_manager: None) -> None:
    """Test that security headers are not added when disabled."""
    app = FastAPI()
    config = SecurityConfig(
        security_headers={"enabled": False},
        enable_redis=False,
        enable_agent=False,
        passive_mode=True,
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/test")
    async def test_endpoint() -> dict[str, str]:
        return {"message": "test"}

    client = TestClient(app)
    response = client.get("/test")

    assert response.status_code == 200
    assert "X-Content-Type-Options" not in response.headers
    assert "X-Frame-Options" not in response.headers


def test_security_headers_on_error_response(reset_headers_manager: None) -> None:
    """Test that security headers are added to error responses."""
    app = FastAPI()

    async def custom_check(request: Any) -> Any:
        return Response(
            "Forbidden by custom check", status_code=403
        )  # pragma: no cover

    config = SecurityConfig(
        security_headers={"enabled": True},
        custom_request_check=custom_check,
        enable_redis=False,
        enable_agent=False,
        passive_mode=False,
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/test")
    async def test_endpoint() -> dict[str, str]:
        return {"message": "test"}  # pragma: no cover

    client = TestClient(app)
    response = client.get("/test")

    assert response.status_code == 403
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "SAMEORIGIN"
    assert response.text == "Forbidden"


@pytest.mark.asyncio
async def test_security_headers_manager_singleton() -> None:
    """Test that SecurityHeadersManager is a singleton."""
    manager1 = SecurityHeadersManager()
    manager2 = SecurityHeadersManager()

    assert manager1 is manager2
    assert manager1 is security_headers_manager


@pytest.mark.asyncio
async def test_headers_caching() -> None:
    """Test that headers are cached properly."""
    manager = SecurityHeadersManager()
    manager.configure(
        enabled=True,
        csp={"default-src": ["'self'"]},
    )

    # First call should generate headers
    headers1 = await manager.get_headers("/test")
    assert "Content-Security-Policy" in headers1

    # Second call should use cache
    headers2 = await manager.get_headers("/test")
    assert headers1 == headers2

    # Different path should generate new headers
    headers3 = await manager.get_headers("/different")
    assert "Content-Security-Policy" in headers3


@pytest.mark.asyncio
async def test_new_default_security_headers() -> None:
    """Test that new security headers are in defaults."""
    manager = SecurityHeadersManager()

    headers = await manager.get_headers()

    # Check all new headers are present
    assert "X-Permitted-Cross-Domain-Policies" in headers
    assert headers["X-Permitted-Cross-Domain-Policies"] == "none"

    assert "X-Download-Options" in headers
    assert headers["X-Download-Options"] == "noopen"

    assert "Cross-Origin-Embedder-Policy" in headers
    assert headers["Cross-Origin-Embedder-Policy"] == "require-corp"

    assert "Cross-Origin-Opener-Policy" in headers
    assert headers["Cross-Origin-Opener-Policy"] == "same-origin"

    assert "Cross-Origin-Resource-Policy" in headers
    assert headers["Cross-Origin-Resource-Policy"] == "same-origin"


@pytest.mark.asyncio
async def test_original_headers_still_present() -> None:
    """Test that original security headers are still included."""
    manager = SecurityHeadersManager()

    headers = await manager.get_headers()

    # Check original headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "SAMEORIGIN"
    assert headers["X-XSS-Protection"] == "1; mode=block"
    assert headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert headers["Permissions-Policy"] == "geolocation=(), microphone=(), camera=()"
