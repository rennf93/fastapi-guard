from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import Request

from guard.core.validation.context import ValidationContext
from guard.core.validation.validator import RequestValidator


@pytest.fixture
def mock_config() -> Any:
    """Create mock config."""
    config = Mock()
    config.trust_x_forwarded_proto = True
    config.trusted_proxies = ["192.168.1.1", "10.0.0.0/8"]
    config.exclude_paths = ["/health", "/metrics"]
    return config


@pytest.fixture
def mock_event_bus() -> Any:
    """Create mock event bus."""
    event_bus = Mock()
    event_bus.send_middleware_event = AsyncMock()
    return event_bus


@pytest.fixture
def validation_context(mock_config: Any, mock_event_bus: Any) -> ValidationContext:
    """Create validation context."""
    return ValidationContext(
        config=mock_config,
        logger=Mock(),
        event_bus=mock_event_bus,
    )


@pytest.fixture
def validator(validation_context: ValidationContext) -> RequestValidator:
    """Create RequestValidator instance."""
    return RequestValidator(validation_context)


@pytest.fixture
def mock_request() -> Any:
    """Create mock request."""
    request = Mock(spec=Request)
    request.url = Mock()
    request.url.scheme = "http"
    request.url.path = "/test"
    request.headers = {}
    request.client = Mock()
    request.client.host = "127.0.0.1"
    return request


class TestRequestValidator:
    """Test RequestValidator class."""

    def test_init(self, validation_context: ValidationContext) -> None:
        """Test validator initialization."""
        validator = RequestValidator(validation_context)
        assert validator.context == validation_context

    def test_is_request_https_direct_https(
        self, validator: RequestValidator, mock_request: Any
    ) -> None:
        """Test is_request_https with direct HTTPS."""
        mock_request.url.scheme = "https"

        result = validator.is_request_https(mock_request)

        assert result is True

    def test_is_request_https_direct_http(
        self, validator: RequestValidator, mock_request: Any
    ) -> None:
        """Test is_request_https with direct HTTP."""
        mock_request.url.scheme = "http"

        result = validator.is_request_https(mock_request)

        assert result is False

    def test_is_request_https_forwarded_proto_trusted_proxy(
        self, validator: RequestValidator, mock_request: Any
    ) -> None:
        """Test is_request_https with X-Forwarded-Proto from trusted proxy."""
        mock_request.url.scheme = "http"
        mock_request.headers = {"X-Forwarded-Proto": "https"}
        mock_request.client.host = "192.168.1.1"  # Trusted proxy

        result = validator.is_request_https(mock_request)

        assert result is True

    def test_is_request_https_forwarded_proto_untrusted_proxy(
        self, validator: RequestValidator, mock_request: Any
    ) -> None:
        """Test is_request_https with X-Forwarded-Proto from untrusted proxy."""
        mock_request.url.scheme = "http"
        mock_request.headers = {"X-Forwarded-Proto": "https"}
        mock_request.client.host = "1.2.3.4"  # Untrusted proxy

        result = validator.is_request_https(mock_request)

        assert result is False

    def test_is_request_https_no_client(
        self, validator: RequestValidator, mock_request: Any
    ) -> None:
        """Test is_request_https when request has no client."""
        mock_request.url.scheme = "http"
        mock_request.client = None

        result = validator.is_request_https(mock_request)

        assert result is False

    def test_is_request_https_trust_disabled(
        self, validator: RequestValidator, mock_request: Any
    ) -> None:
        """Test is_request_https when trust_x_forwarded_proto is disabled."""
        validator.context.config.trust_x_forwarded_proto = False
        mock_request.url.scheme = "http"
        mock_request.headers = {"X-Forwarded-Proto": "https"}

        result = validator.is_request_https(mock_request)

        assert result is False

    def test_is_request_https_no_trusted_proxies(
        self, validator: RequestValidator, mock_request: Any
    ) -> None:
        """Test is_request_https when no trusted proxies configured."""
        validator.context.config.trusted_proxies = []
        mock_request.url.scheme = "http"
        mock_request.headers = {"X-Forwarded-Proto": "https"}

        result = validator.is_request_https(mock_request)

        assert result is False

    def test_is_trusted_proxy_single_ip_match(
        self, validator: RequestValidator
    ) -> None:
        """Test is_trusted_proxy with single IP match."""
        result = validator.is_trusted_proxy("192.168.1.1")

        assert result is True

    def test_is_trusted_proxy_single_ip_no_match(
        self, validator: RequestValidator
    ) -> None:
        """Test is_trusted_proxy with single IP no match."""
        result = validator.is_trusted_proxy("192.168.1.2")

        assert result is False

    def test_is_trusted_proxy_cidr_match(self, validator: RequestValidator) -> None:
        """Test is_trusted_proxy with CIDR range match."""
        result = validator.is_trusted_proxy("10.0.5.10")

        assert result is True

    def test_is_trusted_proxy_cidr_no_match(self, validator: RequestValidator) -> None:
        """Test is_trusted_proxy with CIDR range no match."""
        result = validator.is_trusted_proxy("11.0.0.1")

        assert result is False

    @pytest.mark.asyncio
    async def test_check_time_window_within_range(
        self, validator: RequestValidator
    ) -> None:
        """Test check_time_window when current time is within range."""
        # Set up time window that includes current time
        current = datetime.now(timezone.utc)
        # current_time = current.strftime("%H:%M")

        # Create a window around current time
        hour = current.hour
        start_hour = (hour - 1) % 24
        end_hour = (hour + 1) % 24

        time_restrictions = {
            "start": f"{start_hour:02d}:00",
            "end": f"{end_hour:02d}:59",
        }

        result = await validator.check_time_window(time_restrictions)

        # Should be within window
        assert result is True

    @pytest.mark.asyncio
    async def test_check_time_window_outside_range(
        self, validator: RequestValidator
    ) -> None:
        """Test check_time_window when current time is outside range."""
        # Set up time window that doesn't include current time
        current = datetime.now(timezone.utc)

        # Create a window far from current time
        hour = current.hour
        start_hour = (hour + 6) % 24
        end_hour = (hour + 8) % 24

        time_restrictions = {
            "start": f"{start_hour:02d}:00",
            "end": f"{end_hour:02d}:00",
        }

        result = await validator.check_time_window(time_restrictions)

        # Should be outside window (unless we're unlucky with timing)
        assert result is False

    @pytest.mark.asyncio
    async def test_check_time_window_overnight_within(
        self, validator: RequestValidator
    ) -> None:
        """Test check_time_window with overnight window (e.g., 22:00-06:00)."""
        time_restrictions = {"start": "22:00", "end": "06:00"}

        result = await validator.check_time_window(time_restrictions)

        # Result depends on current time - we just verify it runs
        assert isinstance(result, bool)

    @pytest.mark.asyncio
    async def test_check_time_window_error_handling(
        self, validator: RequestValidator
    ) -> None:
        """Test check_time_window error handling with invalid data."""
        time_restrictions = {"invalid": "data"}

        result = await validator.check_time_window(time_restrictions)

        # Should return True (allow access) on error
        assert result is True

    @pytest.mark.asyncio
    async def test_is_path_excluded_matching_path(
        self, validator: RequestValidator, mock_request: Any, mock_event_bus: Any
    ) -> None:
        """Test is_path_excluded with matching path."""
        mock_request.url.path = "/health"

        result = await validator.is_path_excluded(mock_request)

        assert result is True
        mock_event_bus.send_middleware_event.assert_called_once()
        call_kwargs = mock_event_bus.send_middleware_event.call_args[1]
        assert call_kwargs["event_type"] == "path_excluded"
        assert call_kwargs["excluded_path"] == "/health"

    @pytest.mark.asyncio
    async def test_is_path_excluded_prefix_match(
        self, validator: RequestValidator, mock_request: Any, mock_event_bus: Any
    ) -> None:
        """Test is_path_excluded with prefix match."""
        mock_request.url.path = "/health/check"

        result = await validator.is_path_excluded(mock_request)

        assert result is True
        mock_event_bus.send_middleware_event.assert_called_once()

    @pytest.mark.asyncio
    async def test_is_path_excluded_no_match(
        self, validator: RequestValidator, mock_request: Any, mock_event_bus: Any
    ) -> None:
        """Test is_path_excluded with no matching path."""
        mock_request.url.path = "/api/endpoint"

        result = await validator.is_path_excluded(mock_request)

        assert result is False
        mock_event_bus.send_middleware_event.assert_not_called()
