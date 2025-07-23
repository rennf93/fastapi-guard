"""
Test configuration specific to fastapi-guard-agent integration tests.

This conftest.py is only loaded for tests in the test_agent directory.
"""

from collections.abc import Generator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from guard_agent.models import AgentConfig, SecurityEvent, SecurityMetric

from guard.models import SecurityConfig


@pytest.fixture
def mock_guard_agent() -> Generator[Any, Any, Any]:
    """Mock the guard_agent module for tests that need it."""
    # Mock the guard_agent module
    mock_guard_agent = MagicMock()
    mock_guard_agent.models = MagicMock()
    mock_guard_agent.models.SecurityEvent = SecurityEvent
    mock_guard_agent.models.SecurityMetric = SecurityMetric
    mock_guard_agent.models.AgentConfig = AgentConfig

    # Mock guard_agent function to return a mock agent handler
    mock_agent_handler = AsyncMock()
    mock_guard_agent_func = MagicMock(return_value=mock_agent_handler)

    # Apply the mock
    with patch.dict(
        "sys.modules",
        {
            "guard_agent": mock_guard_agent,
            "guard_agent.models": mock_guard_agent.models,
        },
    ):
        with (
            patch(
                "guard.handlers.dynamic_rule_handler.SecurityEvent",
                SecurityEvent,
                create=True,
            ),
            patch(
                "guard.decorators.base.SecurityEvent",
                SecurityEvent,
                create=True,
            ),
            patch(
                "guard.models.AgentConfig",
                AgentConfig,
                create=True,
            ),
            patch(
                "guard.middleware.guard_agent",
                mock_guard_agent_func,
                create=True,
            ),
            patch(
                "guard.middleware.SecurityEvent",
                SecurityEvent,
                create=True,
            ),
            patch(
                "guard.middleware.SecurityMetric",
                SecurityMetric,
                create=True,
            ),
        ):
            yield mock_guard_agent


# Mock Redis and IPInfo to prevent initialization issues
@pytest.fixture(autouse=True)
def mock_dependencies(mock_guard_agent: MagicMock) -> Generator[Any, Any, Any]:
    """Mock external dependencies to prevent connection attempts."""
    with (
        patch(
            "guard.handlers.redis_handler.RedisManager.initialize",
            new_callable=AsyncMock,
        ),
        patch("guard.handlers.ipinfo_handler.IPInfoManager.__new__") as mock_ipinfo,
    ):
        # Return a mock IPInfoManager instance
        mock_ipinfo_instance = MagicMock()
        mock_ipinfo.return_value = mock_ipinfo_instance
        yield


@pytest.fixture
def config() -> SecurityConfig:
    """Create a test security config."""
    return SecurityConfig(
        enable_agent=True,
        agent_api_key="test-api-key",
        agent_endpoint="http://test.example.com",
        enable_dynamic_rules=True,
        dynamic_rule_interval=5,
        enable_penetration_detection=True,
        enable_ip_banning=True,
        enable_rate_limiting=True,
        rate_limit=100,
        rate_limit_window=60,
        auto_ban_threshold=5,
    )


@pytest.fixture
def mock_agent_handler() -> AsyncMock:
    """Create a mock agent handler."""
    handler = AsyncMock()
    handler.get_dynamic_rules = AsyncMock()
    handler.send_event = AsyncMock()
    return handler


@pytest.fixture
def mock_redis_handler() -> AsyncMock:
    """Create a mock redis handler."""
    return AsyncMock()
