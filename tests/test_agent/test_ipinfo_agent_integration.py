# tests/test_agent/test_ipinfo_agent_integration.py
import asyncio
import logging
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard.handlers.ipinfo_handler import IPInfoManager


class TestIPInfoManagerAgentIntegration:
    """Test IPInfoManager agent integration."""

    @pytest.mark.asyncio
    async def test_initialize_agent(self, cleanup_ipinfo_singleton: None) -> None:
        """Test initialize_agent method."""
        manager = IPInfoManager(token="test-token")
        mock_agent = AsyncMock()

        await manager.initialize_agent(mock_agent)

        assert manager.agent_handler is mock_agent

    @pytest.mark.asyncio
    async def test_send_geo_event_no_agent_handler(
        self, cleanup_ipinfo_singleton: None
    ) -> None:
        """Test _send_geo_event when agent_handler is None."""
        manager = IPInfoManager(token="test-token")
        manager.agent_handler = None

        # Should return early without any action
        await manager._send_geo_event(
            event_type="geo_lookup_failed",
            ip_address="192.168.1.1",
            action_taken="blocked",
            reason="test reason",
        )

        # Test passes if no exception is raised

    @pytest.mark.asyncio
    async def test_send_geo_event_success(self, cleanup_ipinfo_singleton: None) -> None:
        """Test _send_geo_event success path."""
        manager = IPInfoManager(token="test-token")
        mock_agent = AsyncMock()
        manager.agent_handler = mock_agent

        await manager._send_geo_event(
            event_type="country_blocked",
            ip_address="192.168.1.100",
            action_taken="request_blocked",
            reason="Country not allowed",
            country="CN",
            rule_type="country_blacklist",
        )

        # Verify event was sent
        mock_agent.send_event.assert_called_once()
        sent_event = mock_agent.send_event.call_args[0][0]

        # Verify event properties
        assert sent_event.event_type == "country_blocked"
        assert sent_event.ip_address == "192.168.1.100"
        assert sent_event.action_taken == "request_blocked"
        assert sent_event.reason == "Country not allowed"
        assert sent_event.metadata["country"] == "CN"
        assert sent_event.metadata["rule_type"] == "country_blacklist"

    @pytest.mark.asyncio
    async def test_send_geo_event_exception_handling(
        self, cleanup_ipinfo_singleton: None, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test _send_geo_event exception handling."""
        manager = IPInfoManager(token="test-token")
        mock_agent = AsyncMock()
        mock_agent.send_event.side_effect = Exception("Network error")
        manager.agent_handler = mock_agent

        # Enable logging
        caplog.set_level(logging.ERROR)

        # Should not raise exception
        await manager._send_geo_event(
            event_type="geo_lookup_failed",
            ip_address="192.168.1.101",
            action_taken="lookup_failed",
            reason="Test failure",
        )

        # Verify error was logged
        assert "Failed to send geo event to agent: Network error" in caplog.text

    @pytest.mark.asyncio
    async def test_initialize_database_download_failure_with_agent(
        self, cleanup_ipinfo_singleton: None
    ) -> None:
        """Test database download failure with agent event."""
        manager = IPInfoManager(token="test-token", db_path=Path("test_data/test.mmdb"))
        mock_agent = AsyncMock()
        manager.agent_handler = mock_agent

        # Mock the download to fail
        with patch.object(manager, "_download_database") as mock_download:
            mock_download.side_effect = Exception("Download failed")

            # Mock _is_db_outdated to return True to trigger download
            with patch.object(manager, "_is_db_outdated", return_value=True):
                await manager.initialize()

        # Verify agent event was sent
        mock_agent.send_event.assert_called_once()
        sent_event = mock_agent.send_event.call_args[0][0]

        assert sent_event.event_type == "geo_lookup_failed"
        assert sent_event.ip_address == "system"
        assert sent_event.action_taken == "database_download_failed"
        assert "Failed to download IPInfo database" in sent_event.reason

    @pytest.mark.asyncio
    async def test_get_country_exception_with_agent(
        self, cleanup_ipinfo_singleton: None
    ) -> None:
        """Test get_country exception with agent event."""
        manager = IPInfoManager(token="test-token")
        mock_agent = AsyncMock()
        manager.agent_handler = mock_agent

        # Mock reader to raise exception
        mock_reader = MagicMock()
        mock_reader.get.side_effect = Exception("Database corrupted")
        manager.reader = mock_reader

        # Call get_country and expect None
        result = manager.get_country("192.168.1.100")
        assert result is None

        # Wait a bit for the async task to be scheduled
        await asyncio.sleep(0.1)

        # Verify agent event was sent via asyncio.create_task
        mock_agent.send_event.assert_called_once()
        sent_event = mock_agent.send_event.call_args[0][0]

        assert sent_event.event_type == "geo_lookup_failed"
        assert sent_event.ip_address == "192.168.1.100"
        assert sent_event.action_taken == "lookup_failed"
        assert "Geographic lookup failed: Database corrupted" in sent_event.reason

    def test_get_country_exception_create_task_fails(
        self, cleanup_ipinfo_singleton: None
    ) -> None:
        """Test get_country when asyncio.create_task fails"""
        manager = IPInfoManager(token="test-token")
        mock_agent = AsyncMock()
        manager.agent_handler = mock_agent

        # Mock reader to raise exception
        mock_reader = MagicMock()
        mock_reader.get.side_effect = Exception("Database error")
        manager.reader = mock_reader

        # Create a mock that tracks if create_task was called and fails
        create_task_called = False

        def mock_create_task(coro: Any) -> Any:
            nonlocal create_task_called
            create_task_called = True
            # Close the coroutine to prevent warning
            coro.close()
            raise RuntimeError("No event loop")

        # Mock asyncio.create_task to raise exception within the ipinfo_handler module
        with patch(
            "guard.handlers.ipinfo_handler.asyncio.create_task",
            side_effect=mock_create_task,
        ):
            # Should return None without raising
            result = manager.get_country("192.168.1.100")
            assert result is None

        # Verify create_task was called and failed
        assert create_task_called
        # Agent send_event should not have been called since create_task failed
        mock_agent.send_event.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_country_exception_no_agent(
        self, cleanup_ipinfo_singleton: None
    ) -> None:
        """Test get_country exception without agent handler."""
        manager = IPInfoManager(token="test-token")
        manager.agent_handler = None

        # Mock reader to raise exception
        mock_reader = MagicMock()
        mock_reader.get.side_effect = Exception("Database error")
        manager.reader = mock_reader

        # Should return None without raising
        result = manager.get_country("192.168.1.100")
        assert result is None

    @pytest.mark.asyncio
    async def test_check_country_access_no_country(
        self, cleanup_ipinfo_singleton: None
    ) -> None:
        """Test check_country_access when country cannot be determined"""
        manager = IPInfoManager(token="test-token")
        mock_agent = AsyncMock()
        manager.agent_handler = mock_agent

        # Mock reader to return None (no country found)
        mock_reader = MagicMock()
        mock_reader.get.return_value = None
        manager.reader = mock_reader

        result, country = await manager.check_country_access(
            "192.168.1.100",
            blocked_countries=["CN", "RU"],
            whitelist_countries=None,
        )

        assert result is True
        assert country is None
        # No event should be sent
        mock_agent.send_event.assert_not_called()

    @pytest.mark.asyncio
    async def test_check_country_access_whitelist_not_in_list(
        self, cleanup_ipinfo_singleton: None
    ) -> None:
        """Test check_country_access with whitelist - country not in list."""
        manager = IPInfoManager(token="test-token")
        mock_agent = AsyncMock()
        manager.agent_handler = mock_agent

        # Mock get_country to return a country not in whitelist
        with patch.object(manager, "get_country", return_value="CN"):
            result, country = await manager.check_country_access(
                "192.168.1.100",
                blocked_countries=[],
                whitelist_countries=["US", "CA", "GB"],
            )

        assert result is False
        assert country == "CN"

        # Verify agent event was sent
        mock_agent.send_event.assert_called_once()
        sent_event = mock_agent.send_event.call_args[0][0]

        assert sent_event.event_type == "country_blocked"
        assert sent_event.ip_address == "192.168.1.100"
        assert sent_event.action_taken == "request_blocked"
        assert sent_event.reason == "Country CN not in allowed list"
        assert sent_event.metadata["country"] == "CN"
        assert sent_event.metadata["rule_type"] == "country_whitelist"

    @pytest.mark.asyncio
    async def test_check_country_access_blacklist_blocked(
        self, cleanup_ipinfo_singleton: None
    ) -> None:
        """Test check_country_access with blacklist - country is blocked."""
        manager = IPInfoManager(token="test-token")
        mock_agent = AsyncMock()
        manager.agent_handler = mock_agent

        # Mock get_country to return a blocked country
        with patch.object(manager, "get_country", return_value="RU"):
            result, country = await manager.check_country_access(
                "192.168.1.100",
                blocked_countries=["CN", "RU", "KP"],
                whitelist_countries=None,
            )

        assert result is False
        assert country == "RU"

        # Verify agent event was sent
        mock_agent.send_event.assert_called_once()
        sent_event = mock_agent.send_event.call_args[0][0]

        assert sent_event.event_type == "country_blocked"
        assert sent_event.ip_address == "192.168.1.100"
        assert sent_event.action_taken == "request_blocked"
        assert sent_event.reason == "Country RU is blocked"
        assert sent_event.metadata["country"] == "RU"
        assert sent_event.metadata["rule_type"] == "country_blacklist"

    @pytest.mark.asyncio
    async def test_check_country_access_allowed(
        self, cleanup_ipinfo_singleton: None
    ) -> None:
        """Test check_country_access when country is allowed."""
        manager = IPInfoManager(token="test-token")
        mock_agent = AsyncMock()
        manager.agent_handler = mock_agent

        # Mock get_country to return an allowed country
        with patch.object(manager, "get_country", return_value="US"):
            result, country = await manager.check_country_access(
                "192.168.1.100",
                blocked_countries=["CN", "RU"],
                whitelist_countries=None,
            )

        assert result is True
        assert country == "US"

        # No event should be sent for allowed access
        mock_agent.send_event.assert_not_called()

    @pytest.mark.asyncio
    async def test_check_country_access_whitelist_in_list(
        self, cleanup_ipinfo_singleton: None
    ) -> None:
        """Test check_country_access with whitelist - country in list."""
        manager = IPInfoManager(token="test-token")
        mock_agent = AsyncMock()
        manager.agent_handler = mock_agent

        # Mock get_country to return a whitelisted country
        with patch.object(manager, "get_country", return_value="US"):
            result, country = await manager.check_country_access(
                "192.168.1.100",
                blocked_countries=["CN", "RU"],
                whitelist_countries=["US", "CA", "GB"],
            )

        assert result is True
        assert country == "US"

        # No event should be sent for allowed access
        mock_agent.send_event.assert_not_called()


@pytest.fixture
def cleanup_ipinfo_singleton() -> Generator[Any, Any, Any]:
    """Cleanup IPInfoManager singleton before and after test."""
    # Reset before test
    IPInfoManager._instance = None

    def custom_new(
        cls: type[IPInfoManager], token: str, db_path: Path | None = None
    ) -> IPInfoManager:
        if cls._instance is None:
            cls._instance = object.__new__(cls)
            cls._instance.token = token
            cls._instance.db_path = db_path or Path("data/ipinfo/country_asn.mmdb")
            cls._instance.reader = None
            cls._instance.redis_handler = None
            cls._instance.agent_handler = None
            cls._instance.logger = logging.getLogger(__name__)

        cls._instance.token = token
        if db_path is not None:
            cls._instance.db_path = db_path
        return cls._instance

    # Patch __new__ with our custom implementation and SecurityEvent
    with (
        patch.object(IPInfoManager, "__new__", custom_new),
        patch(
            "guard.handlers.ipinfo_handler.SecurityEvent",
            create=True,
        ) as mock_event,
    ):
        from guard_agent.models import SecurityEvent

        mock_event.side_effect = SecurityEvent
        yield

    # Reset after test
    IPInfoManager._instance = None
