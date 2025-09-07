from collections.abc import AsyncGenerator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from guard.handlers.security_headers_handler import security_headers_manager
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig


@pytest.fixture
async def reset_headers_manager() -> AsyncGenerator[None, None]:
    """Reset security headers manager state before each test."""
    await security_headers_manager.reset()
    yield
    await security_headers_manager.reset()


def test_security_headers_none_config(reset_headers_manager: None) -> None:
    """Test when config.security_headers is None."""
    app = FastAPI()

    # Create config with security_headers as None
    config = SecurityConfig(
        security_headers=None,
        enable_redis=False,
        enable_agent=False,
        passive_mode=True,
    )

    # Add middleware
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/test")
    async def test_endpoint() -> dict[str, str]:
        return {"message": "test"}

    # Make request
    client = TestClient(app)
    response = client.get("/test")

    # Check that security headers manager is disabled
    assert security_headers_manager.enabled is False
    assert response.status_code == 200

    # No security headers should be present
    assert "X-Content-Type-Options" not in response.headers
    assert "X-Frame-Options" not in response.headers
    assert "X-XSS-Protection" not in response.headers
