from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import Request, Response

from guard.core.checks.base import SecurityCheck


class ConcreteSecurityCheck(SecurityCheck):
    """Concrete implementation of SecurityCheck for testing."""

    async def check(self, request: Request) -> Response | None:
        """Implement abstract check method."""
        return None

    @property
    def check_name(self) -> str:
        """Implement abstract check_name property."""
        return "test_check"


@pytest.fixture
def mock_middleware() -> Mock:
    """Create mock middleware."""
    middleware = Mock()
    middleware.config = Mock()
    middleware.config.passive_mode = False
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(return_value=Response(status_code=403))
    return middleware


@pytest.fixture
def security_check(mock_middleware: Mock) -> ConcreteSecurityCheck:
    """Create ConcreteSecurityCheck instance."""
    return ConcreteSecurityCheck(mock_middleware)


@pytest.fixture
def mock_request() -> Mock:
    """Create mock request."""
    request = Mock(spec=Request)
    request.url = Mock()
    request.url.path = "/test"
    request.client = Mock()
    request.client.host = "127.0.0.1"
    return request


class TestSecurityCheck:
    """Test SecurityCheck base class."""

    def test_cannot_instantiate_abstract_class(self, mock_middleware: Mock) -> None:
        """Test that SecurityCheck cannot be instantiated directly."""
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            SecurityCheck(mock_middleware)  # type: ignore

    def test_init(self, mock_middleware: Mock) -> None:
        """Test SecurityCheck initialization."""
        check = ConcreteSecurityCheck(mock_middleware)
        assert check.middleware == mock_middleware
        assert check.config == mock_middleware.config
        assert check.logger == mock_middleware.logger

    @pytest.mark.asyncio
    async def test_check_abstract_method(
        self, security_check: ConcreteSecurityCheck, mock_request: Mock
    ) -> None:
        """Test abstract check method implementation."""
        result = await security_check.check(mock_request)
        assert result is None

    def test_check_name_abstract_property(
        self, security_check: ConcreteSecurityCheck
    ) -> None:
        """Test abstract check_name property implementation."""
        assert security_check.check_name == "test_check"

    @pytest.mark.asyncio
    async def test_send_event(
        self,
        security_check: ConcreteSecurityCheck,
        mock_request: Mock,
        mock_middleware: Mock,
    ) -> None:
        """Test send_event method."""
        await security_check.send_event(
            event_type="test_event",
            request=mock_request,
            action_taken="blocked",
            reason="test reason",
            extra_data="test",
        )

        mock_middleware.event_bus.send_middleware_event.assert_called_once_with(
            event_type="test_event",
            request=mock_request,
            action_taken="blocked",
            reason="test reason",
            extra_data="test",
        )

    @pytest.mark.asyncio
    async def test_send_event_no_extra_kwargs(
        self,
        security_check: ConcreteSecurityCheck,
        mock_request: Mock,
        mock_middleware: Mock,
    ) -> None:
        """Test send_event method without extra kwargs."""
        await security_check.send_event(
            event_type="test_event",
            request=mock_request,
            action_taken="allowed",
            reason="passed checks",
        )

        mock_middleware.event_bus.send_middleware_event.assert_called_once_with(
            event_type="test_event",
            request=mock_request,
            action_taken="allowed",
            reason="passed checks",
        )

    @pytest.mark.asyncio
    async def test_create_error_response(
        self, security_check: ConcreteSecurityCheck, mock_middleware: Mock
    ) -> None:
        """Test create_error_response method."""
        response = await security_check.create_error_response(403, "Forbidden")

        assert response.status_code == 403
        mock_middleware.create_error_response.assert_called_once_with(403, "Forbidden")

    @pytest.mark.asyncio
    async def test_create_error_response_different_codes(
        self, security_check: ConcreteSecurityCheck, mock_middleware: Mock
    ) -> None:
        """Test create_error_response with different status codes."""
        mock_middleware.create_error_response.reset_mock()
        mock_middleware.create_error_response.return_value = Response(status_code=429)

        response = await security_check.create_error_response(429, "Too Many Requests")

        assert response.status_code == 429
        mock_middleware.create_error_response.assert_called_once_with(
            429, "Too Many Requests"
        )

    def test_is_passive_mode_false(self, security_check: ConcreteSecurityCheck) -> None:
        """Test is_passive_mode when passive mode is disabled."""
        result = security_check.is_passive_mode()
        assert result is False

    def test_is_passive_mode_true(
        self, security_check: ConcreteSecurityCheck, mock_middleware: Mock
    ) -> None:
        """Test is_passive_mode when passive mode is enabled."""
        mock_middleware.config.passive_mode = True
        result = security_check.is_passive_mode()
        assert result is True
