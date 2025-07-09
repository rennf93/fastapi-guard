"""
Test configuration specific to fastapi-guard-agent integration tests.

This conftest.py is only loaded for tests in the test_agent directory.
"""

from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from guard_agent.models import SecurityEvent

from guard.models import SecurityConfig


@pytest.fixture
def mock_guard_agent() -> Generator[Any, Any, Any]:
    """Mock the guard_agent module for tests that need it."""
    # Mock the guard_agent module
    mock_guard_agent = MagicMock()
    mock_guard_agent.models = MagicMock()
    mock_guard_agent.models.SecurityEvent = SecurityEvent

    # Apply the mock
    with patch.dict(
        "sys.modules",
        {
            "guard_agent": mock_guard_agent,
            "guard_agent.models": mock_guard_agent.models,
        },
    ):
        with patch(
            "guard.handlers.dynamic_rule_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ):
            yield mock_guard_agent


@pytest.fixture
def ipinfo_db_path(tmp_path: Path) -> Path:
    """Override ipinfo_db_path fixture."""
    return tmp_path / "test.mmdb"


@pytest.fixture
def security_config(ipinfo_db_path: Path) -> SecurityConfig:
    """Override security_config fixture with mocked IPInfoManager."""
    with patch("guard.handlers.ipinfo_handler.IPInfoManager.__new__") as mock_ipinfo:
        mock_ipinfo_instance = MagicMock()
        mock_ipinfo.return_value = mock_ipinfo_instance

        return SecurityConfig(
            geo_ip_handler=mock_ipinfo_instance,
            enable_redis=False,
            enable_dynamic_rules=True,
            dynamic_rule_interval=5,
        )


@pytest.fixture
async def security_middleware() -> MagicMock:
    """Override security_middleware fixture."""
    mock_middleware = MagicMock()
    mock_middleware.setup_logger = AsyncMock()
    mock_middleware.reset = AsyncMock()
    return mock_middleware
