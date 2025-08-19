"""Tests for security headers integration via SecurityMiddleware."""
from typing import Dict

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig


def test_security_headers_integration() -> None:
    """Test that security headers are correctly added to responses via SecurityMiddleware."""
    app = FastAPI()

    @app.get("/")
    async def read_root() -> Dict[str, str]:
        return {"message": "Hello World"}

    config = SecurityConfig(
        csp_directives={
            "default-src": ["'self'"],
            "script-src": ["'self'", "trusted.cdn.com"],
            "style-src": ["'self'"],
        },
        hsts_max_age=31536000,
        frame_options="DENY",
        content_type_options="nosniff",
        xss_protection="1; mode=block",
        referrer_policy="no-referrer",
        permissions_policy={
            "geolocation": ["'self'"],
            "camera": ["'none'"],
        },
        cross_origin_opener_policy="same-origin",
        cross_origin_resource_policy="same-origin",
        cross_origin_embedder_policy="require-corp",
    )
    app.add_middleware(SecurityMiddleware, config=config)
    
    client = TestClient(app)
    response = client.get("/")
    
    # Check that security headers are present
    assert "content-security-policy" in response.headers
    assert "strict-transport-security" in response.headers
    assert "x-frame-options" in response.headers
    assert "x-content-type-options" in response.headers
    assert "x-xss-protection" in response.headers
    assert "referrer-policy" in response.headers
    assert "permissions-policy" in response.headers
    assert "cross-origin-opener-policy" in response.headers
    assert "cross-origin-resource-policy" in response.headers
    assert "cross-origin-embedder-policy" in response.headers
    
    # Check specific values
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-xss-protection"] == "1; mode=block"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert "script-src 'self' trusted.cdn.com" in response.headers["content-security-policy"]
    assert "geolocation=('self')" in response.headers["permissions-policy"]
    assert "camera=()" in response.headers["permissions-policy"]
    assert response.headers["cross-origin-opener-policy"] == "same-origin"
    assert response.headers["cross-origin-resource-policy"] == "same-origin"
    assert response.headers["cross-origin-embedder-policy"] == "require-corp"


def test_security_headers_default_values() -> None:
    """Test that default values are used when not specified."""
    app = FastAPI()

    @app.get("/")
    async def read_root() -> Dict[str, str]:
        return {"message": "Hello World"}

    # Add middleware with minimal configuration
    config = SecurityConfig()
    app.add_middleware(SecurityMiddleware, config=config)
    
    client = TestClient(app)
    response = client.get("/")
    
    # Check default values
    assert response.headers["x-frame-options"] == "SAMEORIGIN"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-xss-protection"] == "1; mode=block"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin"
    assert response.headers["cross-origin-resource-policy"] == "same-origin"
    assert response.headers["cross-origin-embedder-policy"] == "require-corp"
    assert "max-age=63072000; includeSubDomains" in response.headers["strict-transport-security"]
    
    # Check that CSP header is not set by default
    assert "content-security-policy" not in response.headers
    # Check that permissions-policy header is not set by default
    assert "permissions-policy" not in response.headers


def test_https_redirect_has_headers() -> None:
    """Ensure HTTPS redirect responses also have security headers applied."""
    app = FastAPI()

    @app.get("/")
    async def read_root() -> Dict[str, str]:
        return {"message": "Hello World"}

    config = SecurityConfig(enforce_https=True)
    app.add_middleware(SecurityMiddleware, config=config)

    client = TestClient(app)
    response = client.get("http://test/")
    assert response.status_code in (301, 307, 308)
    assert "x-frame-options" in response.headers


def test_build_csp() -> None:
    """Test building Content Security Policy header via handler."""
    from guard.handlers.headers_handler import headers_handler

    csp = {
        "default-src": ["'self'"],
        "script-src": ["'self'", "*.example.com"],
        "style-src": ["'self'", "'unsafe-inline'"],
    }
    result = headers_handler._build_csp(csp)  # type: ignore[attr-defined]
    assert "default-src 'self'" in result
    assert "script-src 'self' *.example.com" in result
    assert "style-src 'self' 'unsafe-inline'" in result


def test_build_permissions_policy() -> None:
    """Test building Permissions Policy header via handler."""
    from guard.handlers.headers_handler import headers_handler

    policy = {
        "geolocation": ["'self'"],
        "camera": ["'none'"],
        "microphone": ["https://example.com"],
        "fullscreen": [],
    }
    result = headers_handler._build_permissions_policy(policy)  
    assert "geolocation=('self')" in result
    assert "camera=()" in result
    assert "microphone=(https://example.com)" in result
    assert "fullscreen=()" in result
