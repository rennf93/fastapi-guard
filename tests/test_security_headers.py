"""Tests for security headers middleware."""
from typing import Dict, List

import pytest
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from starlette.types import ASGIApp, Receive, Scope, Send
from guard.handlers.security_headers import SecurityHeadersMiddleware


def test_security_headers_middleware() -> None:
    """Test that security headers are correctly added to responses."""
    app = FastAPI()
    
    @app.get("/")
    async def read_root() -> Dict[str, str]:
        return {"message": "Hello World"}
    
    # Add middleware with test configuration
    app.add_middleware(
        SecurityHeadersMiddleware,
        csp={
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
    app.add_middleware(SecurityHeadersMiddleware)
    
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


def test_security_headers_non_http_requests() -> None:
    """Test that non-HTTP requests are passed through without modification."""
    class MockApp:
        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            assert scope["type"] == "websocket"
            await send({"type": "websocket.accept"})
    
    app = MockApp()
    middleware = SecurityHeadersMiddleware(app)
    
    async def receive() -> dict:
        return {"type": "websocket.connect"}
    
    send_called = False
    
    async def send(message: dict) -> None:
        nonlocal send_called
        send_called = True
        assert message == {"type": "websocket.accept"}
    
    # Call the middleware with a WebSocket scope
    import asyncio
    asyncio.run(middleware({"type": "websocket"}, receive, send))
    assert send_called, "Send should have been called with the original message"


def test_build_csp() -> None:
    """Test building Content Security Policy header."""
    middleware = SecurityHeadersMiddleware(lambda x: x)
    csp = {
        "default-src": ["'self'"],
        "script-src": ["'self'", "*.example.com"],
        "style-src": ["'self'", "'unsafe-inline'"],
    }
    result = middleware._build_csp(csp)
    assert "default-src 'self'" in result
    assert "script-src 'self' *.example.com" in result
    assert "style-src 'self' 'unsafe-inline'" in result


def test_build_permissions_policy() -> None:
    """Test building Permissions Policy header."""
    middleware = SecurityHeadersMiddleware(lambda x: x)
    policy = {
        "geolocation": ["'self'"],
        "camera": ["'none'"],
        "microphone": ["https://example.com"],
        "fullscreen": [],
    }
    result = middleware._build_permissions_policy(policy)
    assert "geolocation=('self')" in result
    assert "camera=()" in result
    assert "microphone=(https://example.com)" in result
    assert "fullscreen=()" in result
