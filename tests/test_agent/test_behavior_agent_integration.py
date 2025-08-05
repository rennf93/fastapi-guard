# tests/test_agent/test_behavior_agent_integration.py
import logging
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from guard.handlers.behavior_handler import BehaviorTracker
from guard.models import SecurityConfig


class TestBehaviorTrackerAgentIntegration:
    """Test BehaviorTracker agent integration."""

    @pytest.mark.asyncio
    async def test_initialize_agent(self) -> None:
        """Test initialize_agent method."""
        config = SecurityConfig()
        tracker = BehaviorTracker(config)
        mock_agent = AsyncMock()

        await tracker.initialize_agent(mock_agent)

        assert tracker.agent_handler is mock_agent

    @pytest.mark.asyncio
    async def test_send_behavior_event_no_agent_handler(self) -> None:
        """Test _send_behavior_event when agent_handler is None."""
        config = SecurityConfig()
        tracker = BehaviorTracker(config)
        tracker.agent_handler = None

        # Should return early without any action
        await tracker._send_behavior_event(
            event_type="behavioral_violation",
            ip_address="192.168.1.1",
            action_taken="log",
            reason="test reason",
        )

        # Test passes if no exception is raised

    @pytest.mark.asyncio
    async def test_send_behavior_event_success(self) -> None:
        """Test _send_behavior_event success path."""
        config = SecurityConfig()
        tracker = BehaviorTracker(config)
        mock_agent = AsyncMock()
        tracker.agent_handler = mock_agent

        await tracker._send_behavior_event(
            event_type="behavioral_violation",
            ip_address="192.168.1.100",
            action_taken="ban",
            reason="Suspicious behavior detected",
            endpoint="/api/test",
            rule_type="usage",
            threshold=10,
            window=3600,
        )

        # Verify event was sent
        mock_agent.send_event.assert_called_once()
        sent_event = mock_agent.send_event.call_args[0][0]

        # Verify event properties
        assert sent_event.event_type == "behavioral_violation"
        assert sent_event.ip_address == "192.168.1.100"
        assert sent_event.action_taken == "ban"
        assert sent_event.reason == "Suspicious behavior detected"
        assert sent_event.metadata["endpoint"] == "/api/test"
        assert sent_event.metadata["rule_type"] == "usage"
        assert sent_event.metadata["threshold"] == 10
        assert sent_event.metadata["window"] == 3600

    @pytest.mark.asyncio
    async def test_send_behavior_event_exception_handling(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test _send_behavior_event exception handling."""
        config = SecurityConfig()
        tracker = BehaviorTracker(config)
        mock_agent = AsyncMock()
        mock_agent.send_event.side_effect = Exception("Network error")
        tracker.agent_handler = mock_agent

        # Enable logging
        caplog.set_level(logging.ERROR)

        # Should not raise exception
        await tracker._send_behavior_event(
            event_type="behavioral_violation",
            ip_address="192.168.1.101",
            action_taken="alert",
            reason="Test failure",
        )

        # Verify error was logged
        assert "Failed to send behavior event to agent: Network error" in caplog.text

    @pytest.mark.asyncio
    async def test_apply_action_with_behavior_event(self) -> None:
        """Test apply_action sends behavior event when agent is configured."""
        config = SecurityConfig()
        tracker = BehaviorTracker(config)
        mock_agent = AsyncMock()
        tracker.agent_handler = mock_agent

        # Import BehaviorRule
        from guard.handlers.behavior_handler import BehaviorRule

        rule = BehaviorRule(rule_type="usage", threshold=5, window=300, action="log")

        await tracker.apply_action(
            rule=rule,
            client_ip="192.168.1.50",
            endpoint_id="/api/data",
            details="Exceeded usage threshold",
        )

        # Verify behavior event was sent
        mock_agent.send_event.assert_called_once()
        sent_event = mock_agent.send_event.call_args[0][0]

        assert sent_event.event_type == "behavioral_violation"
        assert sent_event.ip_address == "192.168.1.50"
        assert sent_event.action_taken == "log"
        assert sent_event.reason == "Behavioral rule violated: Exceeded usage threshold"
        assert sent_event.metadata["endpoint"] == "/api/data"
        assert sent_event.metadata["rule_type"] == "usage"
        assert sent_event.metadata["threshold"] == 5
        assert sent_event.metadata["window"] == 300


# Patch SecurityEvent for all tests in this module
@pytest.fixture(autouse=True)
def patch_security_event() -> Any:
    """Patch SecurityEvent for behavior handler tests."""
    with patch(
        "guard.handlers.behavior_handler.SecurityEvent", create=True
    ) as mock_event:
        from guard_agent.models import SecurityEvent

        mock_event.side_effect = SecurityEvent
        yield mock_event
