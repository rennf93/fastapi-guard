from collections.abc import AsyncGenerator

import pytest
from fastapi import FastAPI
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


def test_cors_headers_with_security_headers(reset_headers_manager: None) -> None:
    """Test CORS headers integration with security headers."""
    app = FastAPI()
    config = SecurityConfig(
        security_headers={"enabled": True},
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["Content-Type"],
        cors_allow_credentials=True,
        enable_redis=False,
        enable_agent=False,
        passive_mode=True,
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/test")
    async def test_endpoint() -> dict[str, str]:
        return {"message": "test"}

    client = TestClient(app)
    response = client.get("/test", headers={"Origin": "https://example.com"})

    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == "https://example.com"
    assert "GET, POST" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Allow-Credentials"] == "true"


@pytest.mark.asyncio
async def test_get_cors_headers_no_config() -> None:
    """Test CORS headers when not configured."""
    manager = SecurityHeadersManager()
    manager.cors_config = None

    headers = await manager.get_cors_headers("https://example.com")

    assert headers == {}


@pytest.mark.asyncio
async def test_get_cors_headers_allowed_origin() -> None:
    """Test CORS headers with allowed origin."""
    manager = SecurityHeadersManager()
    manager.cors_config = {
        "origins": ["https://example.com", "https://app.example.com"],
        "allow_methods": ["GET", "POST"],
        "allow_headers": ["Content-Type"],
        "allow_credentials": True,
    }

    headers = await manager.get_cors_headers("https://example.com")

    assert headers["Access-Control-Allow-Origin"] == "https://example.com"
    assert "GET, POST" in headers["Access-Control-Allow-Methods"]
    assert "Content-Type" in headers["Access-Control-Allow-Headers"]
    assert headers["Access-Control-Allow-Credentials"] == "true"
    assert headers["Access-Control-Max-Age"] == "3600"


@pytest.mark.asyncio
async def test_get_cors_headers_wildcard() -> None:
    """Test CORS headers with wildcard origin."""
    manager = SecurityHeadersManager()
    manager.cors_config = {
        "origins": ["*"],
        "allow_methods": ["GET"],
        "allow_headers": ["*"],
    }

    headers = await manager.get_cors_headers("https://any-origin.com")

    assert headers["Access-Control-Allow-Origin"] == "*"
    assert "GET" in headers["Access-Control-Allow-Methods"]


@pytest.mark.asyncio
async def test_get_cors_headers_disallowed_origin() -> None:
    """Test CORS headers with disallowed origin."""
    manager = SecurityHeadersManager()
    manager.cors_config = {
        "origins": ["https://example.com"],
        "allow_methods": ["GET", "POST"],
    }

    headers = await manager.get_cors_headers("https://evil.com")

    assert headers == {}


@pytest.mark.asyncio
async def test_get_cors_headers_invalid_config() -> None:
    """Test CORS headers with invalid configuration."""
    manager = SecurityHeadersManager()

    # Invalid origins type (not a list)
    manager.cors_config = {
        "origins": "https://example.com",
        "allow_methods": ["GET"],
    }

    headers = await manager.get_cors_headers("https://example.com")
    assert headers == {}

    # Invalid allow_methods type
    manager.cors_config = {
        "origins": ["https://example.com"],
        "allow_methods": "GET",
        "allow_headers": ["Content-Type"],
    }

    headers = await manager.get_cors_headers("https://example.com")
    # Should use default methods
    assert "GET, POST" in headers["Access-Control-Allow-Methods"]

    # Invalid allow_headers type
    manager.cors_config = {
        "origins": ["https://example.com"],
        "allow_methods": ["GET"],
        "allow_headers": "Content-Type",
    }

    headers = await manager.get_cors_headers("https://example.com")
    # Should use default headers
    assert "*" in headers["Access-Control-Allow-Headers"]


@pytest.mark.asyncio
async def test_cors_wildcard_with_credentials_blocked() -> None:
    """Test that wildcard origin with credentials is blocked."""
    manager = SecurityHeadersManager()

    # Configure CORS with wildcard and credentials (should be blocked)
    manager.configure(cors_origins=["*"], cors_allow_credentials=True)

    # Verify credentials are disabled
    assert manager.cors_config is not None
    assert manager.cors_config["allow_credentials"] is False

    # Test get_cors_headers now blocks credentials but still returns headers
    headers = await manager.get_cors_headers("https://example.com")
    # Should return headers but without credentials
    assert "Access-Control-Allow-Origin" in headers
    assert "Access-Control-Allow-Credentials" not in headers


@pytest.mark.asyncio
async def test_cors_wildcard_runtime_credential_blocking(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test runtime blocking when wildcard origin has credentials enabled."""
    manager = SecurityHeadersManager()

    # Manually set up CORS config with wildcard and credentials
    # (simulating a configuration that bypassed the configure() validation)
    manager.cors_config = {
        "origins": ["*"],
        "allow_credentials": True,  # This should trigger runtime blocking
        "allow_methods": ["GET", "POST"],
        "allow_headers": ["*"],
    }

    # Test get_cors_headers blocks and logs warning
    headers = await manager.get_cors_headers("https://example.com")

    # Should return empty dict (blocked)
    assert headers == {}

    # Should log warning
    assert (
        "Credentials cannot be used with wildcard origin - blocking CORS" in caplog.text
    )  # noqa: E501


@pytest.mark.asyncio
async def test_cors_specific_origin_with_credentials_allowed() -> None:
    """Test that specific origins with credentials are allowed."""
    manager = SecurityHeadersManager()

    manager.configure(cors_origins=["https://trusted.com"], cors_allow_credentials=True)

    # Verify configuration is accepted
    assert manager.cors_config is not None
    assert manager.cors_config["allow_credentials"] is True

    # Test get_cors_headers returns proper headers
    headers = await manager.get_cors_headers("https://trusted.com")
    assert headers["Access-Control-Allow-Origin"] == "https://trusted.com"
    assert headers["Access-Control-Allow-Credentials"] == "true"


@pytest.mark.asyncio
async def test_cors_multiple_origins_validation() -> None:
    """Test CORS with multiple specific origins."""
    manager = SecurityHeadersManager()

    manager.configure(
        cors_origins=["https://site1.com", "https://site2.com"],
        cors_allow_credentials=True,
    )

    # Test allowed origin
    headers = await manager.get_cors_headers("https://site1.com")
    assert headers["Access-Control-Allow-Origin"] == "https://site1.com"
    assert headers["Access-Control-Allow-Credentials"] == "true"

    # Test disallowed origin
    headers = await manager.get_cors_headers("https://evil.com")
    assert headers == {}
