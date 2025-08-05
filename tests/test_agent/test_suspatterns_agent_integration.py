# tests/test_agent/test_suspatterns_agent_integration.py
import logging
from collections.abc import Generator
from unittest.mock import AsyncMock

import pytest

from guard.handlers.suspatterns_handler import SusPatternsManager


class TestSusPatternsManagerAgentIntegration:
    """Test SusPatternsManager agent integration"""

    @pytest.mark.asyncio
    async def test_initialize_agent(self, cleanup_suspatterns_singleton: None) -> None:
        """Test initialize_agent method."""
        # Reset singleton
        SusPatternsManager._instance = None

        manager = SusPatternsManager()
        mock_agent = AsyncMock()

        await manager.initialize_agent(mock_agent)

        assert manager.agent_handler is mock_agent

    @pytest.mark.asyncio
    async def test_send_pattern_event_exception_handling(
        self, cleanup_suspatterns_singleton: None, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test _send_pattern_event exception handling."""
        # Reset singleton
        SusPatternsManager._instance = None

        manager = SusPatternsManager()
        mock_agent = AsyncMock()
        mock_agent.send_event.side_effect = Exception("Network error")
        manager.agent_handler = mock_agent

        # Enable logging
        caplog.set_level(logging.ERROR)

        # Should not raise exception
        await manager._send_pattern_event(
            event_type="pattern_detected",
            ip_address="192.168.1.100",
            action_taken="blocked",
            reason="Suspicious pattern detected",
            extra_data="test",
        )

        # Verify error was logged
        assert "Failed to send pattern event to agent: Network error" in caplog.text

    @pytest.mark.asyncio
    async def test_detect_pattern_match_no_match(
        self, cleanup_suspatterns_singleton: None
    ) -> None:
        """Test detect_pattern_match when no pattern matches."""
        # Reset singleton
        SusPatternsManager._instance = None

        manager = SusPatternsManager()
        mock_agent = AsyncMock()
        manager.agent_handler = mock_agent

        # Test with content that doesn't match any patterns
        content = "This is completely safe content with no suspicious patterns"
        ip_address = "192.168.1.100"

        result, matched_pattern = await manager.detect_pattern_match(
            content, ip_address, "test_context"
        )

        assert result is False
        assert matched_pattern is None
        # Verify no event was sent
        mock_agent.send_event.assert_not_called()

    @pytest.mark.asyncio
    async def test_add_pattern_with_agent_event(
        self, cleanup_suspatterns_singleton: None
    ) -> None:
        """Test add_pattern with agent event."""
        # Reset singleton
        SusPatternsManager._instance = None

        manager = SusPatternsManager()
        mock_agent = AsyncMock()
        manager.agent_handler = mock_agent

        # Add custom pattern
        pattern = r"malicious\d+"
        await manager.add_pattern(pattern, custom=True)

        # Verify pattern was added
        assert pattern in manager.custom_patterns

        # Verify agent event was sent
        mock_agent.send_event.assert_called_once()
        sent_event = mock_agent.send_event.call_args[0][0]

        assert sent_event.event_type == "pattern_added"
        assert sent_event.ip_address == "system"
        assert sent_event.action_taken == "pattern_added"
        assert sent_event.reason == "Custom pattern added to detection system"
        assert sent_event.metadata["pattern"] == pattern
        assert sent_event.metadata["pattern_type"] == "custom"
        assert sent_event.metadata["total_patterns"] == 1

    @pytest.mark.asyncio
    async def test_remove_pattern_with_agent_event(
        self, cleanup_suspatterns_singleton: None
    ) -> None:
        """Test remove_pattern with agent event."""
        # Reset singleton
        SusPatternsManager._instance = None

        manager = SusPatternsManager()
        mock_agent = AsyncMock()
        manager.agent_handler = mock_agent

        # Clear any existing custom patterns to ensure clean state
        manager.custom_patterns.clear()
        manager.compiled_custom_patterns.clear()

        # First add a custom pattern
        pattern = r"test_pattern\d+"
        await manager.add_pattern(pattern, custom=True)

        # Clear the mock to ignore the add event
        mock_agent.reset_mock()

        # Remove the pattern
        result = await manager.remove_pattern(pattern, custom=True)

        assert result is True
        assert pattern not in manager.custom_patterns

        # Verify agent event was sent
        mock_agent.send_event.assert_called_once()
        sent_event = mock_agent.send_event.call_args[0][0]

        assert sent_event.event_type == "pattern_removed"
        assert sent_event.ip_address == "system"
        assert sent_event.action_taken == "pattern_removed"
        assert sent_event.reason == "Custom pattern removed from detection system"
        assert sent_event.metadata["pattern"] == pattern
        assert sent_event.metadata["pattern_type"] == "custom"
        assert sent_event.metadata["total_patterns"] == 0


@pytest.fixture
def cleanup_suspatterns_singleton() -> Generator[None, None, None]:
    """Cleanup SusPatternsManager singleton before and after test."""
    # Store original state before any test modifications
    original_instance = SusPatternsManager._instance

    # Reset singleton before test
    SusPatternsManager._instance = None

    yield

    # Full cleanup after test
    if SusPatternsManager._instance is not None:
        # Clear any custom patterns added during test
        SusPatternsManager._instance.custom_patterns.clear()  # type: ignore
        SusPatternsManager._instance.compiled_custom_patterns.clear()

        # Clear any default patterns that were added during tests
        # (patterns is a class attribute, always exists)
        original_len = len(SusPatternsManager.patterns)
        while len(SusPatternsManager._instance.patterns) > original_len:
            SusPatternsManager._instance.patterns.pop()  # pragma: no cover
            SusPatternsManager._instance.compiled_patterns.pop()  # pragma: no cover

    # Restore original instance
    SusPatternsManager._instance = original_instance
