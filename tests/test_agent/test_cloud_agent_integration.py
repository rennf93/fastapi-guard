# tests/test_agent/test_cloud_agent_integration.py
import ipaddress
import logging
from collections.abc import Generator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from guard.handlers.cloud_handler import CloudManager


class TestCloudManagerAgentIntegration:
    """Test CloudManager agent integration."""

    @pytest.mark.asyncio
    async def test_initialize_agent(self) -> None:
        """Test initialize_agent method."""
        manager = CloudManager()
        mock_agent = AsyncMock()

        await manager.initialize_agent(mock_agent)

        assert manager.agent_handler is mock_agent

    def test_get_cloud_provider_details_invalid_ip(self) -> None:
        """Test get_cloud_provider_details with invalid IP."""
        manager = CloudManager()

        # Add some test IP ranges
        manager.ip_ranges["AWS"] = {ipaddress.ip_network("10.0.0.0/8")}

        # Test with invalid IP address
        result = manager.get_cloud_provider_details("not-an-ip-address")

        assert result is None

    @pytest.mark.asyncio
    async def test_send_cloud_detection_event_no_agent(self) -> None:
        """Test send_cloud_detection_event when agent_handler is None."""
        manager = CloudManager()
        manager.agent_handler = None

        # Should return early without any action
        await manager.send_cloud_detection_event(
            ip="192.168.1.1",
            provider="AWS",
            network="192.168.0.0/16",
            action_taken="request_blocked",
        )

        # Test passes if no exception is raised

    @pytest.mark.asyncio
    async def test_send_cloud_detection_event_with_agent(self) -> None:
        """Test send_cloud_detection_event with agent."""
        manager = CloudManager()
        mock_agent = AsyncMock()
        manager.agent_handler = mock_agent

        await manager.send_cloud_detection_event(
            ip="192.168.1.100",
            provider="AWS",
            network="192.168.0.0/16",
            action_taken="request_blocked",
        )

        # Verify event was sent
        mock_agent.send_event.assert_called_once()
        sent_event = mock_agent.send_event.call_args[0][0]

        # Verify event properties
        assert sent_event.event_type == "cloud_blocked"
        assert sent_event.ip_address == "192.168.1.100"
        assert sent_event.action_taken == "request_blocked"
        assert sent_event.reason == "IP belongs to blocked cloud provider: AWS"
        assert sent_event.metadata["cloud_provider"] == "AWS"
        assert sent_event.metadata["network"] == "192.168.0.0/16"

    @pytest.mark.asyncio
    async def test_send_cloud_event_no_agent_handler(self) -> None:
        """Test _send_cloud_event when agent_handler is None."""
        manager = CloudManager()
        manager.agent_handler = None

        # Should return early without any action
        await manager._send_cloud_event(
            event_type="cloud_blocked",
            ip_address="192.168.1.1",
            action_taken="blocked",
            reason="test reason",
        )

        # Test passes if no exception is raised

    @pytest.mark.asyncio
    async def test_send_cloud_event_success(self) -> None:
        """Test _send_cloud_event success path."""
        manager = CloudManager()
        mock_agent = AsyncMock()
        manager.agent_handler = mock_agent

        await manager._send_cloud_event(
            event_type="cloud_blocked",
            ip_address="192.168.1.100",
            action_taken="request_blocked",
            reason="Cloud provider blocked",
            cloud_provider="GCP",
            network="10.0.0.0/8",
            extra_data="test",
        )

        # Verify event was sent
        mock_agent.send_event.assert_called_once()
        sent_event = mock_agent.send_event.call_args[0][0]

        # Verify event properties
        assert sent_event.event_type == "cloud_blocked"
        assert sent_event.ip_address == "192.168.1.100"
        assert sent_event.action_taken == "request_blocked"
        assert sent_event.reason == "Cloud provider blocked"
        assert sent_event.metadata["cloud_provider"] == "GCP"
        assert sent_event.metadata["network"] == "10.0.0.0/8"
        assert sent_event.metadata["extra_data"] == "test"

    @pytest.mark.asyncio
    async def test_send_cloud_event_exception_handling(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test _send_cloud_event exception handling."""
        manager = CloudManager()
        mock_agent = AsyncMock()
        mock_agent.send_event.side_effect = Exception("Network error")
        manager.agent_handler = mock_agent

        # Enable logging
        caplog.set_level(logging.ERROR)

        # Should not raise exception
        await manager._send_cloud_event(
            event_type="cloud_blocked",
            ip_address="192.168.1.101",
            action_taken="blocked",
            reason="Test failure",
        )

        # Verify error was logged
        assert "Failed to send cloud event to agent: Network error" in caplog.text


@pytest.fixture(autouse=True)
def cleanup_cloud_singleton() -> Generator[Any, Any, Any]:
    """Cleanup CloudManager singleton before and after test."""
    # Store original state
    original_instance = CloudManager._instance
    original_ip_ranges = None
    if original_instance:
        # Deep copy the ip_ranges to restore later
        original_ip_ranges = {
            provider: ranges.copy()
            for provider, ranges in original_instance.ip_ranges.items()
        }

    # Reset before test
    CloudManager._instance = None

    def custom_new(cls: type[CloudManager]) -> CloudManager:
        if cls._instance is None:
            cls._instance = object.__new__(cls)
            cls._instance.ip_ranges = {
                "AWS": set(),
                "GCP": set(),
                "Azure": set(),
            }
            cls._instance.redis_handler = None
            cls._instance.agent_handler = None
            cls._instance.logger = logging.getLogger(__name__)
        return cls._instance

    # Patch __new__ with our custom implementation and SecurityEvent
    with (
        patch.object(CloudManager, "__new__", custom_new),
        patch("guard.handlers.cloud_handler.SecurityEvent", create=True) as mock_event,
    ):
        from guard_agent.models import SecurityEvent

        mock_event.side_effect = SecurityEvent
        yield

    # Restore original state completely
    CloudManager._instance = original_instance
    if original_instance and original_ip_ranges:
        # Restore the original ip_ranges
        original_instance.ip_ranges = original_ip_ranges
