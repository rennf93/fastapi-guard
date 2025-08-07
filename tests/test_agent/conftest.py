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
    import sys
    import types

    mock_guard_agent_module = types.ModuleType("guard_agent")
    mock_guard_agent_module.SecurityEvent = SecurityEvent  # type: ignore
    mock_guard_agent_module.SecurityMetric = SecurityMetric  # type: ignore
    mock_guard_agent_module.AgentConfig = AgentConfig  # type: ignore

    mock_models_module = types.ModuleType("guard_agent.models")
    mock_models_module.SecurityEvent = SecurityEvent  # type: ignore
    mock_models_module.SecurityMetric = SecurityMetric  # type: ignore
    mock_models_module.AgentConfig = AgentConfig  # type: ignore
    mock_guard_agent_module.models = mock_models_module  # type: ignore

    # Mock guard_agent function to return a mock agent handler
    mock_agent_handler = AsyncMock()
    mock_guard_agent_func = MagicMock(return_value=mock_agent_handler)
    mock_guard_agent_module.guard_agent = mock_guard_agent_func  # type: ignore

    original_modules = {}
    modules_to_mock = [
        "guard_agent",
        "guard_agent.models",
    ]

    for module_name in modules_to_mock:
        if module_name in sys.modules:
            original_modules[module_name] = sys.modules[module_name]

    sys.modules["guard_agent"] = mock_guard_agent_module
    sys.modules["guard_agent.models"] = mock_models_module

    with (
        patch(
            "guard.handlers.behavior_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "guard.handlers.cloud_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
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
            "guard.handlers.ipban_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "guard.handlers.ipinfo_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "guard.handlers.ratelimit_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "guard.handlers.redis_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "guard.handlers.suspatterns_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "guard.utils.SecurityEvent",
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
        try:
            yield mock_guard_agent_module
        finally:
            # Restore original modules
            for module_name in modules_to_mock:
                if module_name in original_modules:
                    sys.modules[module_name] = original_modules[module_name]
                elif module_name in sys.modules:  # pragma: no cover
                    del sys.modules[module_name]


# Mock Redis, IPInfo, and CloudManager to prevent initialization issues
@pytest.fixture(autouse=True)
def mock_dependencies(mock_guard_agent: MagicMock) -> Generator[Any, Any, Any]:
    """Mock external dependencies to prevent connection attempts."""
    with (
        patch(
            "guard.handlers.redis_handler.RedisManager.initialize",
            new_callable=AsyncMock,
        ),
        patch("guard.handlers.ipinfo_handler.IPInfoManager.__new__") as mock_ipinfo,
        patch("guard.handlers.cloud_handler.CloudManager.__new__") as mock_cloud,
    ):
        # Return mock instances
        mock_ipinfo_instance = MagicMock()
        mock_ipinfo.return_value = mock_ipinfo_instance

        mock_cloud_instance = MagicMock()
        mock_cloud.return_value = mock_cloud_instance
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
