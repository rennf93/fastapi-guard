# tests/test_agent/test_ipban_handler.py
import logging
from collections.abc import Generator
from typing import Any
from unittest.mock import AsyncMock

import pytest

from guard.handlers.ipban_handler import IPBanManager


class TestIPBanManagerAgentIntegration:
    """Test IPBanManager agent integration"""

    @pytest.mark.asyncio
    async def test_initialize_agent(self, cleanup_ipban_singleton: None) -> None:
        """Test initialize_agent method"""
        # Reset singleton
        IPBanManager._instance = None

        manager = IPBanManager()
        mock_agent = AsyncMock()

        await manager.initialize_agent(mock_agent)

        assert manager.agent_handler is mock_agent

    @pytest.mark.asyncio
    async def test_send_ban_event_success(self, cleanup_ipban_singleton: None) -> None:
        """Test _send_ban_event success path"""
        # Reset singleton
        IPBanManager._instance = None

        manager = IPBanManager()
        manager.agent_handler = AsyncMock()

        await manager.ban_ip("192.168.1.100", 3600, "test_reason")

        # Verify event was sent
        manager.agent_handler.send_event.assert_called_once()
        sent_event = manager.agent_handler.send_event.call_args[0][0]

        # Verify event properties
        assert sent_event.event_type == "ip_banned"
        assert sent_event.ip_address == "192.168.1.100"
        assert sent_event.action_taken == "banned"
        assert sent_event.reason == "test_reason"
        assert sent_event.metadata["duration"] == 3600

    @pytest.mark.asyncio
    async def test_send_ban_event_failure(
        self, caplog: pytest.LogCaptureFixture, cleanup_ipban_singleton: None
    ) -> None:
        """Test _send_ban_event exception handling."""
        # Reset singleton
        IPBanManager._instance = None

        manager = IPBanManager()
        manager.agent_handler = AsyncMock()
        manager.agent_handler.send_event.side_effect = Exception("Network error")

        with caplog.at_level(logging.ERROR):
            await manager.ban_ip("192.168.1.101", 3600, "test_reason")

        # Verify error was logged
        assert "Failed to send ban event to agent: Network error" in caplog.text

    @pytest.mark.asyncio
    async def test_unban_ip_with_agent(self, cleanup_ipban_singleton: None) -> None:
        """Test unban_ip with agent."""
        # Reset singleton
        IPBanManager._instance = None

        manager = IPBanManager()
        manager.agent_handler = AsyncMock()
        manager.redis_handler = AsyncMock()

        # First ban an IP
        await manager.ban_ip("192.168.1.103", 3600, "test_reason")
        manager.agent_handler.send_event.reset_mock()

        # Now unban
        await manager.unban_ip("192.168.1.103")

        # Verify IP was removed from cache
        assert await manager.is_ip_banned("192.168.1.103") is False

        # Verify Redis delete was called
        # Note: delete might be called twice - once in unban_ip and once in is_ip_banned
        manager.redis_handler.delete.assert_called_with("banned_ips", "192.168.1.103")

        # Verify event was sent
        manager.agent_handler.send_event.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_unban_event_success(
        self, cleanup_ipban_singleton: None
    ) -> None:
        """Test _send_unban_event success path."""
        # Reset singleton
        IPBanManager._instance = None

        manager = IPBanManager()
        manager.agent_handler = AsyncMock()

        # Ban and then unban
        await manager.ban_ip("172.16.0.1", 1800, "test")
        manager.agent_handler.send_event.reset_mock()

        await manager.unban_ip("172.16.0.1")

        # Check the unban event
        sent_event = manager.agent_handler.send_event.call_args[0][0]
        assert sent_event.event_type == "ip_unbanned"
        assert sent_event.ip_address == "172.16.0.1"
        assert sent_event.action_taken == "unbanned"
        assert sent_event.reason == "dynamic_rule_whitelist"
        assert sent_event.metadata == {"action": "unban"}

    @pytest.mark.asyncio
    async def test_send_unban_event_failure(
        self, caplog: pytest.LogCaptureFixture, cleanup_ipban_singleton: None
    ) -> None:
        """Test _send_unban_event exception handling."""
        # Reset singleton
        IPBanManager._instance = None

        manager = IPBanManager()
        manager.agent_handler = AsyncMock()

        # Configure the mock to fail only on the second call (unban)
        manager.agent_handler.send_event.side_effect = [
            None,
            Exception("Connection timeout"),
        ]

        # First ban an IP
        await manager.ban_ip("192.168.1.105", 3600, "test_reason")

        with caplog.at_level(logging.ERROR):
            await manager.unban_ip("192.168.1.105")

        # Verify error was logged
        assert "Failed to send unban event to agent: Connection timeout" in caplog.text


# Cleanup fixture
@pytest.fixture
def cleanup_ipban_singleton() -> Generator[Any, Any, Any]:
    """Reset IPBanManager singleton before and after each test."""
    # Reset before test
    IPBanManager._instance = None
    yield
    # Reset after test
    IPBanManager._instance = None
