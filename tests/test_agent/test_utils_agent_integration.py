# tests/test_agent/test_utils_agent_integration.py
import logging
from datetime import datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard.utils import send_agent_event


class TestUtilsAgentIntegration:
    """Test utils.py agent integration functions."""

    @pytest.mark.asyncio
    async def test_send_agent_event_no_handler(self) -> None:
        """Test send_agent_event returns early when handler is None."""
        # Should return without any action
        await send_agent_event(
            agent_handler=None,
            event_type="test_event",
            ip_address="192.168.1.1",
            action_taken="test_action",
            reason="test reason",
        )
        # Test passes if no exception is raised

    @pytest.mark.asyncio
    async def test_send_agent_event_success_without_request(self) -> None:
        """Test send_agent_event success path without request object."""
        mock_agent = AsyncMock()

        await send_agent_event(
            agent_handler=mock_agent,
            event_type="ip_banned",
            ip_address="192.168.1.100",
            action_taken="banned",
            reason="Suspicious activity detected",
            metadata={"extra_field": "extra_value"},
        )

        # Verify event was sent
        mock_agent.send_event.assert_called_once()
        sent_event = mock_agent.send_event.call_args[0][0]

        # Verify event properties
        assert sent_event.event_type == "ip_banned"
        assert sent_event.ip_address == "192.168.1.100"
        assert sent_event.action_taken == "banned"
        assert sent_event.reason == "Suspicious activity detected"
        assert sent_event.endpoint is None
        assert sent_event.method is None
        assert sent_event.user_agent is None
        assert sent_event.country is None
        assert sent_event.metadata == {"extra_field": "extra_value"}
        assert isinstance(sent_event.timestamp, datetime)

    @pytest.mark.asyncio
    async def test_send_agent_event_exception_handling(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test send_agent_event handles exceptions gracefully."""
        mock_agent = AsyncMock()
        mock_agent.send_event.side_effect = Exception("Network error")

        # Enable logging
        caplog.set_level(logging.ERROR)

        # Should not raise exception
        await send_agent_event(
            agent_handler=mock_agent,
            event_type="suspicious_request",
            ip_address="192.168.1.100",
            action_taken="test_action",
            reason="test reason",
        )

        # Verify error was logged
        assert "Failed to send agent event: Network error" in caplog.text

    @pytest.mark.asyncio
    async def test_send_agent_event_with_request(self) -> None:
        """Test send_agent_event extracts request information properly."""
        mock_agent = AsyncMock()

        # Create mock request
        mock_request = MagicMock()
        mock_request.url = MagicMock()
        mock_request.url.path = "/api/v1/test"
        mock_request.method = "GET"
        mock_request.headers = MagicMock()
        mock_request.headers.get = MagicMock(return_value="TestBrowser/1.0")

        await send_agent_event(
            agent_handler=mock_agent,
            event_type="suspicious_request",
            ip_address="192.168.1.100",
            action_taken="logged",
            reason="Test with request",
            request=mock_request,
        )

        # Verify event was sent
        mock_agent.send_event.assert_called_once()
        sent_event = mock_agent.send_event.call_args[0][0]

        # Verify request fields were extracted
        assert sent_event.endpoint == "/api/v1/test"
        assert sent_event.method == "GET"
        assert sent_event.user_agent == "TestBrowser/1.0"

        # Verify headers.get was called with "User-Agent"
        mock_request.headers.get.assert_called_once_with("User-Agent")


# Fixture to ensure SecurityEvent is available
@pytest.fixture(autouse=True)
def patch_security_event() -> Any:
    """Patch SecurityEvent for all tests."""
    with patch("guard.utils.SecurityEvent", create=True) as mock_event:
        from guard_agent.models import SecurityEvent

        mock_event.side_effect = SecurityEvent
        yield
