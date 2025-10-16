from collections.abc import Awaitable, Callable
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import Request, Response

from guard.core.bypass.context import BypassContext
from guard.core.bypass.handler import BypassHandler
from guard.decorators.base import RouteConfig


@pytest.fixture
def mock_response_factory() -> Mock:
    """Create mock response factory."""
    factory = Mock()
    factory.apply_modifier = AsyncMock(return_value=Response(status_code=200))
    return factory


@pytest.fixture
def mock_validator() -> Mock:
    """Create mock validator."""
    validator = Mock()
    validator.is_path_excluded = AsyncMock(return_value=False)
    return validator


@pytest.fixture
def mock_route_resolver() -> Mock:
    """Create mock route resolver."""
    resolver = Mock()
    resolver.should_bypass_check = Mock(return_value=False)
    return resolver


@pytest.fixture
def mock_event_bus() -> Mock:
    """Create mock event bus."""
    event_bus = Mock()
    event_bus.send_middleware_event = AsyncMock()
    return event_bus


@pytest.fixture
def mock_config() -> Mock:
    """Create mock config."""
    config = Mock()
    config.passive_mode = False
    return config


@pytest.fixture
def bypass_context(
    mock_config: Mock,
    mock_response_factory: Mock,
    mock_validator: Mock,
    mock_route_resolver: Mock,
    mock_event_bus: Mock,
) -> BypassContext:
    """Create bypass context."""
    return BypassContext(
        config=mock_config,
        logger=Mock(),
        response_factory=mock_response_factory,
        validator=mock_validator,
        route_resolver=mock_route_resolver,
        event_bus=mock_event_bus,
    )


@pytest.fixture
def bypass_handler(bypass_context: BypassContext) -> BypassHandler:
    """Create BypassHandler instance."""
    return BypassHandler(bypass_context)


@pytest.fixture
def mock_request() -> Mock:
    """Create mock request."""
    request = Mock(spec=Request)
    request.url = Mock()
    request.url.path = "/test"
    request.client = Mock()
    request.client.host = "127.0.0.1"
    return request


@pytest.fixture
def call_next() -> Callable[[Request], Awaitable[Response]]:
    """Create call_next mock."""

    async def _call_next(request: Request) -> Response:
        return Response(status_code=200, content="OK")

    return _call_next


class TestBypassHandler:
    """Test BypassHandler class."""

    def test_init(self, bypass_context: BypassContext) -> None:
        """Test BypassHandler initialization."""
        handler = BypassHandler(bypass_context)
        assert handler.context == bypass_context

    @pytest.mark.asyncio
    async def test_handle_passthrough_no_client(
        self,
        bypass_handler: BypassHandler,
        mock_request: Mock,
        call_next: Callable[[Request], Awaitable[Response]],
        mock_response_factory: Mock,
    ) -> None:
        """Test handle_passthrough when request has no client."""
        mock_request.client = None

        response = await bypass_handler.handle_passthrough(mock_request, call_next)

        assert response is not None
        assert response.status_code == 200
        mock_response_factory.apply_modifier.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_passthrough_excluded_path(
        self,
        bypass_handler: BypassHandler,
        mock_request: Mock,
        call_next: Callable[[Request], Awaitable[Response]],
        mock_validator: Mock,
        mock_response_factory: Mock,
    ) -> None:
        """Test handle_passthrough when path is excluded."""
        mock_validator.is_path_excluded.return_value = True

        response = await bypass_handler.handle_passthrough(mock_request, call_next)

        assert response is not None
        assert response.status_code == 200
        mock_validator.is_path_excluded.assert_called_once_with(mock_request)
        mock_response_factory.apply_modifier.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_passthrough_no_bypass(
        self,
        bypass_handler: BypassHandler,
        mock_request: Mock,
        call_next: Callable[[Request], Awaitable[Response]],
        mock_validator: Mock,
    ) -> None:
        """Test handle_passthrough when no bypass conditions met."""
        mock_validator.is_path_excluded.return_value = False

        response = await bypass_handler.handle_passthrough(mock_request, call_next)

        assert response is None
        mock_validator.is_path_excluded.assert_called_once_with(mock_request)

    @pytest.mark.asyncio
    async def test_handle_security_bypass_no_route_config(
        self,
        bypass_handler: BypassHandler,
        mock_request: Mock,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> None:
        """Test handle_security_bypass when no route config provided."""
        response = await bypass_handler.handle_security_bypass(
            mock_request, call_next, None
        )

        assert response is None

    @pytest.mark.asyncio
    async def test_handle_security_bypass_should_not_bypass(
        self,
        bypass_handler: BypassHandler,
        mock_request: Mock,
        call_next: Callable[[Request], Awaitable[Response]],
        mock_route_resolver: Mock,
    ) -> None:
        """Test handle_security_bypass when should_bypass_check returns False."""
        route_config = RouteConfig()
        route_config.bypassed_checks = {"ip_check"}
        mock_route_resolver.should_bypass_check.return_value = False

        response = await bypass_handler.handle_security_bypass(
            mock_request, call_next, route_config
        )

        assert response is None
        mock_route_resolver.should_bypass_check.assert_called_once_with(
            "all", route_config
        )

    @pytest.mark.asyncio
    async def test_handle_security_bypass_active_mode(
        self,
        bypass_handler: BypassHandler,
        mock_request: Mock,
        call_next: Callable[[Request], Awaitable[Response]],
        mock_route_resolver: Mock,
        mock_event_bus: Mock,
        mock_response_factory: Mock,
        bypass_context: BypassContext,
    ) -> None:
        """Test handle_security_bypass in active mode (passive_mode=False)."""
        route_config = RouteConfig()
        route_config.bypassed_checks = {"all"}
        mock_route_resolver.should_bypass_check.return_value = True
        bypass_context.config.passive_mode = False

        response = await bypass_handler.handle_security_bypass(
            mock_request, call_next, route_config
        )

        assert response is not None
        assert response.status_code == 200
        mock_event_bus.send_middleware_event.assert_called_once()
        call_args = mock_event_bus.send_middleware_event.call_args[1]
        assert call_args["event_type"] == "security_bypass"
        assert call_args["action_taken"] == "all_checks_bypassed"
        assert call_args["endpoint"] == "/test"
        mock_response_factory.apply_modifier.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_security_bypass_passive_mode(
        self,
        bypass_handler: BypassHandler,
        mock_request: Mock,
        call_next: Callable[[Request], Awaitable[Response]],
        mock_route_resolver: Mock,
        mock_event_bus: Mock,
        mock_response_factory: Mock,
        bypass_context: BypassContext,
    ) -> None:
        """Test handle_security_bypass in passive mode (passive_mode=True)."""
        route_config = RouteConfig()
        route_config.bypassed_checks = {"all"}
        mock_route_resolver.should_bypass_check.return_value = True
        bypass_context.config.passive_mode = True

        response = await bypass_handler.handle_security_bypass(
            mock_request, call_next, route_config
        )

        # In passive mode, should return None instead of processing
        assert response is None
        mock_event_bus.send_middleware_event.assert_called_once()
        # Should NOT call response factory in passive mode
        mock_response_factory.apply_modifier.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_security_bypass_with_multiple_bypassed_checks(
        self,
        bypass_handler: BypassHandler,
        mock_request: Mock,
        call_next: Callable[[Request], Awaitable[Response]],
        mock_route_resolver: Mock,
        mock_event_bus: Mock,
        bypass_context: BypassContext,
    ) -> None:
        """Test handle_security_bypass with multiple bypassed checks."""
        route_config = RouteConfig()
        route_config.bypassed_checks = {"ip_check", "rate_limit", "https_check"}
        mock_route_resolver.should_bypass_check.return_value = True
        bypass_context.config.passive_mode = False

        response = await bypass_handler.handle_security_bypass(
            mock_request, call_next, route_config
        )

        assert response is not None
        mock_event_bus.send_middleware_event.assert_called_once()
        call_args = mock_event_bus.send_middleware_event.call_args[1]
        assert set(call_args["bypassed_checks"]) == {
            "ip_check",
            "rate_limit",
            "https_check",
        }
