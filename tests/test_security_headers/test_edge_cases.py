from collections.abc import AsyncGenerator

import pytest

from guard.handlers.security_headers_handler import (
    SecurityHeadersManager,
    reset_global_state,
)


@pytest.fixture
async def headers_manager() -> AsyncGenerator[SecurityHeadersManager, None]:
    """Create a fresh headers manager for testing."""
    # Reset before and after test
    await reset_global_state()
    yield SecurityHeadersManager()
    await reset_global_state()


@pytest.mark.asyncio
async def test_reset_global_state() -> None:
    """Test the reset_global_state function."""
    # Save the current singleton instance
    original_instance = SecurityHeadersManager._instance

    try:
        # Reset the singleton's _instance to None
        # to allow a new instance to be created
        SecurityHeadersManager._instance = None

        # Create a new manager and modify it
        manager = SecurityHeadersManager()
        manager.custom_headers = {"X-Test": "value"}
        manager.enabled = False

        # Reset the singleton instance to None again
        # so reset_global_state can create a new one
        SecurityHeadersManager._instance = None

        # Call reset_global_state
        await reset_global_state()

        # Get the new manager
        from guard.handlers.security_headers_handler import (
            security_headers_manager as new_manager,
        )

        # The new manager should have default state
        assert new_manager.enabled is True
        assert len(new_manager.custom_headers) == 0

    finally:
        # Restore the original singleton instance for other tests
        SecurityHeadersManager._instance = original_instance


@pytest.mark.asyncio
async def test_get_headers_with_cached_non_dict_value(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test get_headers when cache contains non-dict value."""
    headers_manager.enabled = True

    # Generate the actual cache key that will be used
    cache_key = headers_manager._generate_cache_key("test_path")

    # Put a non-dict value in cache
    headers_manager.headers_cache[cache_key] = "invalid_value"

    # Should generate new headers and replace the invalid cache
    headers = await headers_manager.get_headers("test_path")

    # Should have default headers
    assert isinstance(headers, dict)
    assert "X-Content-Type-Options" in headers
    assert "X-Frame-Options" in headers

    # Cache should now have valid dict
    assert isinstance(headers_manager.headers_cache[cache_key], dict)


@pytest.mark.asyncio
async def test_complete_secure_configuration() -> None:
    """Test a complete secure configuration with all features."""
    manager = SecurityHeadersManager()

    # Configure with all security features
    manager.configure(
        # CSP with safe directives
        csp={
            "default-src": ["'self'"],
            "script-src": ["'self'", "https://cdn.example.com"],
            "style-src": ["'self'", "'nonce-abc123'"],
        },
        # HSTS with preload
        hsts_max_age=63072000,  # 2 years
        hsts_include_subdomains=True,
        hsts_preload=True,
        # CORS with specific origins
        cors_origins=["https://app.example.com"],
        cors_allow_credentials=True,
        # Custom validated headers
        custom_headers={
            "X-Custom-Security": "enabled",
            "X-Request-ID": "123456",
        },
    )

    # Get headers and verify complete configuration
    headers = await manager.get_headers("/api/endpoint")

    # CSP should be present
    assert "Content-Security-Policy" in headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]

    # HSTS should be present with all directives
    assert "Strict-Transport-Security" in headers
    hsts = headers["Strict-Transport-Security"]
    assert "max-age=63072000" in hsts
    assert "includeSubDomains" in hsts
    assert "preload" in hsts

    # Custom headers should be present
    assert headers["X-Custom-Security"] == "enabled"
    assert headers["X-Request-ID"] == "123456"

    # CORS headers for allowed origin
    cors_headers = await manager.get_cors_headers("https://app.example.com")
    assert cors_headers["Access-Control-Allow-Origin"] == "https://app.example.com"
    assert cors_headers["Access-Control-Allow-Credentials"] == "true"
