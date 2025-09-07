import asyncio
from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard.handlers.security_headers_handler import (
    SecurityHeadersManager,
    security_headers_manager,
)


@pytest.fixture
async def headers_manager() -> AsyncGenerator[SecurityHeadersManager, None]:
    """Create a fresh headers manager for testing."""
    # Reset before and after test
    await security_headers_manager.reset()
    yield security_headers_manager
    await security_headers_manager.reset()


@pytest.mark.asyncio
async def test_initialize_agent(headers_manager: SecurityHeadersManager) -> None:
    """Test Agent initialization for headers manager."""
    mock_agent = AsyncMock()

    await headers_manager.initialize_agent(mock_agent)

    assert headers_manager.agent_handler == mock_agent


@pytest.mark.asyncio
async def test_send_headers_applied_event_no_agent(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test sending event when agent is not configured."""
    headers_manager.agent_handler = None

    # Should not raise when agent is None
    await headers_manager._send_headers_applied_event(
        "/api/test", {"X-Content-Type-Options": "nosniff"}
    )


@pytest.mark.asyncio
async def test_send_headers_applied_event_with_mock_agent(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test that _send_headers_applied_event attempts to send when agent configured."""
    # This tests the structure without requiring guard_agent module
    mock_agent = MagicMock()
    mock_agent.send_event = AsyncMock()

    headers_manager.agent_handler = mock_agent

    headers = {
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
    }

    # The method will try to import guard_agent.SecurityEvent
    # which won't exist in test environment, so it will catch the exception
    await headers_manager._send_headers_applied_event("/api/test", headers)

    # The agent handler should still be set
    assert headers_manager.agent_handler == mock_agent


@pytest.mark.asyncio
async def test_send_headers_event_with_actual_exception(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test _send_headers_applied_event when send_event raises exception."""
    mock_agent = MagicMock()
    mock_agent.send_event = AsyncMock(side_effect=Exception("Network error"))

    headers_manager.agent_handler = mock_agent

    # Mock the guard_agent module import
    import sys

    mock_guard_agent = MagicMock()
    mock_event_class = MagicMock()
    mock_event_instance = MagicMock()
    mock_event_class.return_value = mock_event_instance
    mock_guard_agent.SecurityEvent = mock_event_class

    # Temporarily add to sys.modules
    sys.modules["guard_agent"] = mock_guard_agent

    try:
        # Should not raise, just log debug
        await headers_manager._send_headers_applied_event(
            "/api/test", {"X-Content-Type-Options": "nosniff"}
        )

        # Event should have been created
        mock_event_class.assert_called_once()

        # send_event should have been called and raised
        mock_agent.send_event.assert_called_once_with(mock_event_instance)
    finally:
        # Clean up
        if "guard_agent" in sys.modules:
            del sys.modules["guard_agent"]


@pytest.mark.asyncio
async def test_send_csp_violation_event_no_agent(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test CSP violation event when agent is not configured."""
    headers_manager.agent_handler = None

    csp_report: dict[str, Any] = {
        "document-uri": "https://example.com/page",
        "violated-directive": "script-src",
        "blocked-uri": "https://evil.com/script.js",
    }

    # Should not raise when agent is None
    await headers_manager._send_csp_violation_event(csp_report)


@pytest.mark.asyncio
async def test_send_csp_violation_event_with_mock_agent(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test that _send_csp_violation_event attempts to send when agent configured."""
    mock_agent = MagicMock()
    mock_agent.send_event = AsyncMock()

    headers_manager.agent_handler = mock_agent

    csp_report: dict[str, Any] = {
        "document-uri": "https://example.com/page",
        "violated-directive": "script-src",
        "blocked-uri": "https://evil.com/script.js",
        "source-file": "https://example.com/app.js",
        "line-number": 42,
    }

    # The method will try to import guard_agent.SecurityEvent
    # which won't exist in test environment, so it will catch the exception
    await headers_manager._send_csp_violation_event(csp_report)

    # The agent handler should still be set
    assert headers_manager.agent_handler == mock_agent


@pytest.mark.asyncio
async def test_send_csp_violation_event_with_actual_exception(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test _send_csp_violation_event when send_event raises exception."""
    mock_agent = MagicMock()
    mock_agent.send_event = AsyncMock(side_effect=Exception("API error"))

    headers_manager.agent_handler = mock_agent

    csp_report: dict[str, Any] = {
        "document-uri": "https://example.com",
        "violated-directive": "script-src",
        "blocked-uri": "https://evil.com/script.js",
    }

    # Mock the guard_agent module import
    import sys

    mock_guard_agent = MagicMock()
    mock_event_class = MagicMock()
    mock_event_instance = MagicMock()
    mock_event_class.return_value = mock_event_instance
    mock_guard_agent.SecurityEvent = mock_event_class

    # Temporarily add to sys.modules
    sys.modules["guard_agent"] = mock_guard_agent

    try:
        # Should not raise, just log debug
        await headers_manager._send_csp_violation_event(csp_report)

        # Event should have been created
        mock_event_class.assert_called_once()

        # send_event should have been called and raised
        mock_agent.send_event.assert_called_once_with(mock_event_instance)
    finally:
        # Clean up
        if "guard_agent" in sys.modules:
            del sys.modules["guard_agent"]


@pytest.mark.asyncio
async def test_validate_csp_report_with_agent(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test CSP report validation with agent configured."""
    mock_agent = MagicMock()
    mock_agent.send_event = AsyncMock()

    headers_manager.agent_handler = mock_agent

    valid_report = {
        "csp-report": {
            "document-uri": "https://example.com",
            "violated-directive": "script-src",
            "blocked-uri": "https://evil.com/script.js",
        }
    }

    result = await headers_manager.validate_csp_report(valid_report)

    assert result is True
    # Agent handler should still be configured
    assert headers_manager.agent_handler == mock_agent


@pytest.mark.asyncio
async def test_get_headers_with_agent(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test getting headers with agent configured."""
    mock_agent = MagicMock()
    mock_agent.send_event = AsyncMock()

    headers_manager.agent_handler = mock_agent
    headers_manager.enabled = True

    # Get headers for a specific path
    headers = await headers_manager.get_headers("/api/secure")

    # Should have default headers
    assert "X-Content-Type-Options" in headers
    assert "X-Frame-Options" in headers

    # Agent handler should still be configured
    assert headers_manager.agent_handler == mock_agent


@pytest.mark.asyncio
async def test_get_headers_no_agent_no_path(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test getting headers without agent and without path."""
    headers_manager.agent_handler = None
    headers_manager.enabled = True

    # Get headers without path
    headers = await headers_manager.get_headers()

    # Should have default headers
    assert "X-Content-Type-Options" in headers
    assert "X-Frame-Options" in headers

    # Cache key should be "default"
    assert "default" in headers_manager.headers_cache


@pytest.mark.asyncio
async def test_get_headers_disabled(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test getting headers when disabled."""
    headers_manager.enabled = False

    headers = await headers_manager.get_headers("/test")

    assert headers == {}


@pytest.mark.asyncio
async def test_concurrent_access_thread_safety() -> None:
    """Test thread safety under concurrent access."""
    manager = SecurityHeadersManager()

    async def configure_and_get_headers(config_id: int) -> dict[str, str]:
        """Configure manager and get headers."""
        manager.configure(custom_headers={f"X-Thread-{config_id}": str(config_id)})
        headers = await manager.get_headers(f"/path/{config_id}")
        return headers

    # Run multiple concurrent configurations
    tasks = [configure_and_get_headers(i) for i in range(10)]

    results = await asyncio.gather(*tasks)

    # All results should be valid (no crashes/corruption)
    assert len(results) == 10
    for result in results:
        assert isinstance(result, dict)
        # Should have base security headers
        assert "X-Content-Type-Options" in result
