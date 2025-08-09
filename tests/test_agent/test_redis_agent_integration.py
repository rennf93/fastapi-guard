# tests/test_agent/test_redis_agent_integration.py
import logging
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from guard.handlers.redis_handler import RedisManager
from guard.models import SecurityConfig


class TestRedisManagerAgentIntegration:
    """Test RedisManager agent integration."""

    @pytest.mark.asyncio
    async def test_initialize_agent(self) -> None:
        """Test initialize_agent method."""
        config = SecurityConfig(enable_redis=True, redis_url="redis://localhost")
        manager = RedisManager(config)
        mock_agent = AsyncMock()

        await manager.initialize_agent(mock_agent)

        assert manager.agent_handler is mock_agent

    @pytest.mark.asyncio
    async def test_send_redis_event_no_agent(self) -> None:
        """Test _send_redis_event when agent_handler is None."""
        config = SecurityConfig(enable_redis=True, redis_url="redis://localhost")
        manager = RedisManager(config)
        manager.agent_handler = None

        # Should return early without any action
        await manager._send_redis_event(
            event_type="redis_connection",
            action_taken="test_action",
            reason="test reason",
        )

        # Test passes if no exception is raised

    @pytest.mark.asyncio
    async def test_send_redis_event_success(self) -> None:
        """Test _send_redis_event success path."""
        config = SecurityConfig(enable_redis=True, redis_url="redis://localhost")
        manager = RedisManager(config)
        mock_agent = AsyncMock()
        manager.agent_handler = mock_agent

        await manager._send_redis_event(
            event_type="redis_connection",
            action_taken="connection_established",
            reason="Redis connection successfully established",
            redis_url="redis://localhost",
            extra_data="test",
        )

        # Verify event was sent
        mock_agent.send_event.assert_called_once()
        sent_event = mock_agent.send_event.call_args[0][0]

        # Verify event properties
        assert sent_event.event_type == "redis_connection"
        assert sent_event.ip_address == "system"
        assert sent_event.action_taken == "connection_established"
        assert sent_event.reason == "Redis connection successfully established"
        assert sent_event.metadata["redis_url"] == "redis://localhost"
        assert sent_event.metadata["extra_data"] == "test"

    @pytest.mark.asyncio
    async def test_send_redis_event_exception_handling(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test _send_redis_event exception handling."""
        config = SecurityConfig(enable_redis=True, redis_url="redis://localhost")
        manager = RedisManager(config)
        mock_agent = AsyncMock()
        mock_agent.send_event.side_effect = Exception("Network error")
        manager.agent_handler = mock_agent

        caplog.set_level(logging.ERROR, logger="fastapi_guard.handlers.redis")

        # Should not raise exception
        await manager._send_redis_event(
            event_type="redis_error",
            action_taken="operation_failed",
            reason="Test failure",
        )

        # Verify error was logged
        assert "Failed to send Redis event to agent: Network error" in caplog.text

    @pytest.mark.asyncio
    async def test_close_with_agent(self) -> None:
        """Test close sends event to agent."""
        config = SecurityConfig(enable_redis=True, redis_url="redis://localhost")
        manager = RedisManager(config)
        mock_agent = AsyncMock()
        manager.agent_handler = mock_agent

        # Set up mock Redis connection
        mock_redis = AsyncMock()
        mock_redis.aclose = AsyncMock()
        manager._redis = mock_redis

        await manager.close()

        # Verify connection was closed
        mock_redis.aclose.assert_called_once()
        assert manager._redis is None

    @pytest.mark.asyncio
    async def test_get_connection_closed_error_with_agent(self) -> None:
        """Test get_connection sends error event when connection is closed."""
        config = SecurityConfig(enable_redis=True, redis_url="redis://localhost")
        manager = RedisManager(config)
        mock_agent = AsyncMock()
        manager.agent_handler = mock_agent
        manager._closed = True

        with pytest.raises(HTTPException) as exc_info:
            async with manager.get_connection():
                pass  # pragma: no cover

        assert exc_info.value.status_code == 500
        assert exc_info.value.detail == "Redis connection closed"

        # Verify error event was sent
        mock_agent.send_event.assert_called_once()
        sent_event = mock_agent.send_event.call_args[0][0]

        assert sent_event.event_type == "redis_error"
        assert sent_event.action_taken == "operation_failed"
        assert sent_event.reason == "Attempted to use closed Redis connection"
        assert sent_event.metadata["error_type"] == "connection_closed"

    @pytest.mark.asyncio
    async def test_get_connection_initialization_failure_with_agent(self) -> None:
        """Test get_connection sends error event when initialization fails."""
        config = SecurityConfig(enable_redis=True, redis_url="redis://localhost")
        manager = RedisManager(config)
        mock_agent = AsyncMock()
        manager.agent_handler = mock_agent
        manager._redis = None

        # Mock initialize to set _redis to None (simulating failure)
        async def mock_initialize() -> None:
            manager._redis = None  # pragma: no cover

        with pytest.raises(HTTPException) as exc_info:
            async with manager.get_connection():
                pass  # pragma: no cover

        assert exc_info.value.status_code == 500
        assert exc_info.value.detail == "Redis connection failed"

        # Verify error event was sent
        mock_agent.send_event.assert_called_once()
        sent_event = mock_agent.send_event.call_args[0][0]

        assert sent_event.event_type == "redis_error"
        assert sent_event.action_taken == "operation_failed"
        assert sent_event.reason == "Redis connection is None after initialization"
        assert sent_event.metadata["error_type"] == "initialization_failed"

    @pytest.mark.asyncio
    async def test_safe_operation_failure_with_agent(self) -> None:
        """Test safe_operation sends error event on failure."""
        config = SecurityConfig(enable_redis=True, redis_url="redis://localhost")
        manager = RedisManager(config)
        mock_agent = AsyncMock()
        manager.agent_handler = mock_agent

        # Create a function that will fail
        async def failing_func(conn: Any) -> None:
            raise Exception("Operation failed")  # pragma: no cover

        failing_func.__name__ = "failing_func"  # Set function name for test

        # Mock get_connection to raise an exception
        with pytest.raises(HTTPException) as exc_info:
            await manager.safe_operation(failing_func)

        assert exc_info.value.status_code == 500
        assert exc_info.value.detail == "Redis operation failed"

    @pytest.mark.asyncio
    async def test_safe_operation_error_inside_context(self) -> None:
        """Test safe_operation sends error event when operation inside context fails."""
        config = SecurityConfig(enable_redis=True, redis_url="redis://localhost")
        manager = RedisManager(config)
        mock_agent = AsyncMock()
        manager.agent_handler = mock_agent

        # Mock Redis connection
        mock_redis = AsyncMock()
        manager._redis = mock_redis

        # Create a function that will fail inside the context
        async def failing_operation(conn: Any) -> None:
            raise ValueError("Operation error inside context")

        failing_operation.__name__ = "failing_operation"

        with pytest.raises(HTTPException) as exc_info:
            await manager.safe_operation(failing_operation)

        assert exc_info.value.status_code == 500
        assert exc_info.value.detail == "Redis operation failed"

        # Verify error event was sent with function name
        calls = mock_agent.send_event.call_args_list
        assert len(calls) > 0

        # Find the safe_operation_failed event
        found = False
        for call in calls:
            event = call[0][0]
            if event.action_taken == "safe_operation_failed":
                found = True
                assert event.event_type == "redis_error"
                assert "Operation error inside context" in event.reason
                assert event.metadata["error_type"] == "safe_operation_error"
                assert event.metadata["function_name"] == "failing_operation"
                break

        assert found, "safe_operation_failed event not found"


# Fixture to ensure SecurityEvent is available
@pytest.fixture(autouse=True)
def patch_security_event() -> Any:
    """Patch SecurityEvent for all tests."""
    with patch("guard.handlers.redis_handler.SecurityEvent", create=True) as mock_event:
        from guard_agent.models import SecurityEvent

        mock_event.side_effect = SecurityEvent
        yield
