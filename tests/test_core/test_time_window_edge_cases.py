from typing import cast
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from guard.core.checks.implementations.time_window import TimeWindowCheck
from guard.models import SecurityConfig


@pytest.fixture
def mock_middleware() -> Mock:
    """Create mock middleware."""
    config = SecurityConfig()
    config.passive_mode = False

    middleware = Mock()
    middleware.config = config
    # Use MagicMock for logger so methods work properly
    middleware.logger = MagicMock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(return_value=Mock(status_code=403))
    return middleware


@pytest.fixture
def time_window_check(mock_middleware: Mock) -> TimeWindowCheck:
    """Create TimeWindowCheck instance."""
    return TimeWindowCheck(mock_middleware)


class TestTimeWindowEdgeCases:
    """Test TimeWindowCheck edge cases."""

    @pytest.mark.asyncio
    async def test_check_time_window_exception_handling(
        self, time_window_check: TimeWindowCheck
    ) -> None:
        """Test _check_time_window handles exceptions and returns True."""
        # Exception handling in _check_time_window
        # Pass invalid time_restrictions to trigger exception
        invalid_restrictions = {"invalid": "data"}  # Missing 'start' and 'end' keys

        result = await time_window_check._check_time_window(invalid_restrictions)

        # Should return True (allow access) when time check fails
        assert result is True
        # Verify logger.error was called
        # Verify logger.error was called - cast for mypy
        cast(MagicMock, time_window_check.logger.error).assert_called_once()

    @pytest.mark.asyncio
    async def test_check_time_window_missing_start_key(
        self, time_window_check: TimeWindowCheck
    ) -> None:
        """Test _check_time_window with missing start key."""
        # Exception when accessing 'start' key
        incomplete_restrictions = {"end": "18:00"}

        result = await time_window_check._check_time_window(incomplete_restrictions)

        assert result is True
        # Verify logger.error was called - cast for mypy
        cast(MagicMock, time_window_check.logger.error).assert_called_once()

    @pytest.mark.asyncio
    async def test_check_time_window_missing_end_key(
        self, time_window_check: TimeWindowCheck
    ) -> None:
        """Test _check_time_window with missing end key."""
        # Exception when accessing 'end' key
        incomplete_restrictions = {"start": "09:00"}

        result = await time_window_check._check_time_window(incomplete_restrictions)

        assert result is True
        # Verify logger.error was called - cast for mypy
        cast(MagicMock, time_window_check.logger.error).assert_called_once()
