from unittest.mock import Mock

import pytest
from fastapi import Request

from guard.core.routing.context import RoutingContext
from guard.core.routing.resolver import RouteConfigResolver
from guard.decorators.base import BaseSecurityDecorator, RouteConfig


@pytest.fixture
def mock_config() -> Mock:
    """Create mock config."""
    config = Mock()
    config.block_cloud_providers = {"aws", "gcp"}
    return config


@pytest.fixture
def mock_guard_decorator() -> BaseSecurityDecorator:
    """Create mock guard decorator."""
    decorator = Mock(spec=BaseSecurityDecorator)
    route_config = RouteConfig()
    route_config.bypassed_checks = {"rate_limit"}
    decorator.get_route_config = Mock(return_value=route_config)
    return decorator


@pytest.fixture
def routing_context(
    mock_config: Mock, mock_guard_decorator: BaseSecurityDecorator
) -> RoutingContext:
    """Create routing context."""
    return RoutingContext(
        config=mock_config,
        logger=Mock(),
        guard_decorator=mock_guard_decorator,
    )


@pytest.fixture
def resolver(routing_context: RoutingContext) -> RouteConfigResolver:
    """Create RouteConfigResolver instance."""
    return RouteConfigResolver(routing_context)


@pytest.fixture
def mock_request() -> Mock:
    """Create mock request."""
    request = Mock(spec=Request)
    request.url = Mock()
    request.url.path = "/api/test"
    request.method = "GET"
    request.scope = {"app": None}
    return request


class TestRouteConfigResolver:
    """Test RouteConfigResolver class."""

    def test_init(self, routing_context: RoutingContext) -> None:
        """Test RouteConfigResolver initialization."""
        resolver = RouteConfigResolver(routing_context)
        assert resolver.context == routing_context

    def test_get_guard_decorator_from_app_state(
        self, resolver: RouteConfigResolver, mock_guard_decorator: BaseSecurityDecorator
    ) -> None:
        """Test get_guard_decorator from app state."""
        app = Mock()
        app.state = Mock()
        app.state.guard_decorator = mock_guard_decorator

        result = resolver.get_guard_decorator(app)
        assert result == mock_guard_decorator

    def test_get_guard_decorator_from_context(
        self, resolver: RouteConfigResolver, mock_guard_decorator: BaseSecurityDecorator
    ) -> None:
        """Test get_guard_decorator from context when app has no state."""
        app = Mock()
        app.state = Mock(spec=[])  # No guard_decorator attribute

        result = resolver.get_guard_decorator(app)
        assert result == mock_guard_decorator

    def test_get_guard_decorator_none_when_not_base_security_decorator(
        self, resolver: RouteConfigResolver
    ) -> None:
        """
        Test returns None when app.state.guard_decorator is wrong type.
        """
        app = Mock()
        app.state = Mock()
        app.state.guard_decorator = "not a decorator"

        result = resolver.get_guard_decorator(app)
        # Should fall back to context decorator
        assert result == resolver.context.guard_decorator

    def test_get_guard_decorator_none_when_no_app(
        self, resolver: RouteConfigResolver
    ) -> None:
        """Test get_guard_decorator with None app."""
        result = resolver.get_guard_decorator(None)
        assert result == resolver.context.guard_decorator

    def test_get_guard_decorator_none_when_context_has_none(self) -> None:
        """Test get_guard_decorator when context has no decorator."""
        context = RoutingContext(config=Mock(), logger=Mock(), guard_decorator=None)
        resolver = RouteConfigResolver(context)

        result = resolver.get_guard_decorator(None)
        assert result is None

    def test_is_matching_route_success(self, resolver: RouteConfigResolver) -> None:
        """Test is_matching_route with successful match."""
        route = Mock()
        route.path = "/api/test"
        route.methods = {"GET", "POST"}
        route.endpoint = Mock()
        route.endpoint._guard_route_id = "test_route_id"

        is_match, route_id = resolver.is_matching_route(route, "/api/test", "GET")
        assert is_match is True
        assert route_id == "test_route_id"

    def test_is_matching_route_no_path_attribute(
        self, resolver: RouteConfigResolver
    ) -> None:
        """Test is_matching_route when route has no path attribute."""
        route = Mock(spec=[])  # No attributes

        is_match, route_id = resolver.is_matching_route(route, "/api/test", "GET")
        assert is_match is False
        assert route_id is None

    def test_is_matching_route_no_methods_attribute(
        self, resolver: RouteConfigResolver
    ) -> None:
        """Test is_matching_route when route has no methods attribute."""
        route = Mock(spec=["path"])
        route.path = "/api/test"
        # No methods attribute

        is_match, route_id = resolver.is_matching_route(route, "/api/test", "GET")
        assert is_match is False
        assert route_id is None

    def test_is_matching_route_path_mismatch(
        self, resolver: RouteConfigResolver
    ) -> None:
        """Test is_matching_route with path mismatch."""
        route = Mock()
        route.path = "/api/other"
        route.methods = {"GET"}

        is_match, route_id = resolver.is_matching_route(route, "/api/test", "GET")
        assert is_match is False
        assert route_id is None

    def test_is_matching_route_method_mismatch(
        self, resolver: RouteConfigResolver
    ) -> None:
        """Test is_matching_route with method not in route methods."""
        route = Mock()
        route.path = "/api/test"
        route.methods = {"POST"}

        is_match, route_id = resolver.is_matching_route(route, "/api/test", "GET")
        assert is_match is False
        assert route_id is None

    def test_is_matching_route_no_endpoint(self, resolver: RouteConfigResolver) -> None:
        """Test is_matching_route when route has no endpoint."""
        route = Mock(spec=["path", "methods"])
        route.path = "/api/test"
        route.methods = {"GET"}
        # No endpoint attribute

        is_match, route_id = resolver.is_matching_route(route, "/api/test", "GET")
        assert is_match is False
        assert route_id is None

    def test_is_matching_route_no_guard_route_id(
        self, resolver: RouteConfigResolver
    ) -> None:
        """Test is_matching_route when endpoint has no _guard_route_id."""
        route = Mock()
        route.path = "/api/test"
        route.methods = {"GET"}
        route.endpoint = Mock(spec=[])  # No _guard_route_id

        is_match, route_id = resolver.is_matching_route(route, "/api/test", "GET")
        assert is_match is False
        assert route_id is None

    def test_get_route_config_success(
        self,
        resolver: RouteConfigResolver,
        mock_request: Mock,
        mock_guard_decorator: BaseSecurityDecorator,
    ) -> None:
        """Test get_route_config with successful match."""
        app = Mock()
        app.state = Mock()
        app.state.guard_decorator = mock_guard_decorator
        mock_request.scope = {"app": app}

        route = Mock()
        route.path = "/api/test"
        route.methods = {"GET"}
        route.endpoint = Mock()
        route.endpoint._guard_route_id = "test_route_id"
        app.routes = [route]

        result = resolver.get_route_config(mock_request)
        assert result is not None
        assert "rate_limit" in result.bypassed_checks

    def test_get_route_config_no_decorator(self, mock_request: Mock) -> None:
        """Test get_route_config when no guard decorator available."""
        context = RoutingContext(config=Mock(), logger=Mock(), guard_decorator=None)
        resolver = RouteConfigResolver(context)

        result = resolver.get_route_config(mock_request)
        assert result is None

    def test_get_route_config_no_app(
        self, resolver: RouteConfigResolver, mock_request: Mock
    ) -> None:
        """Test get_route_config when request has no app."""
        mock_request.scope = {"app": None}

        result = resolver.get_route_config(mock_request)
        assert result is None

    def test_get_route_config_no_matching_route(
        self,
        resolver: RouteConfigResolver,
        mock_request: Mock,
        mock_guard_decorator: BaseSecurityDecorator,
    ) -> None:
        """Test get_route_config when no route matches."""
        app = Mock()
        app.state = Mock()
        app.state.guard_decorator = mock_guard_decorator
        mock_request.scope = {"app": app}

        route = Mock()
        route.path = "/api/other"
        route.methods = {"GET"}
        app.routes = [route]

        result = resolver.get_route_config(mock_request)
        assert result is None

    def test_should_bypass_check_no_config(self, resolver: RouteConfigResolver) -> None:
        """Test should_bypass_check with no route config."""
        result = resolver.should_bypass_check("rate_limit", None)
        assert result is False

    def test_should_bypass_check_specific_check(
        self, resolver: RouteConfigResolver
    ) -> None:
        """Test should_bypass_check with specific check in bypassed_checks."""
        route_config = RouteConfig()
        route_config.bypassed_checks = {"rate_limit", "ip_check"}

        result = resolver.should_bypass_check("rate_limit", route_config)
        assert result is True

    def test_should_bypass_check_all_checks(
        self, resolver: RouteConfigResolver
    ) -> None:
        """Test should_bypass_check with 'all' in bypassed_checks."""
        route_config = RouteConfig()
        route_config.bypassed_checks = {"all"}

        result = resolver.should_bypass_check("any_check", route_config)
        assert result is True

    def test_should_bypass_check_not_bypassed(
        self, resolver: RouteConfigResolver
    ) -> None:
        """Test should_bypass_check when check is not bypassed."""
        route_config = RouteConfig()
        route_config.bypassed_checks = {"ip_check"}

        result = resolver.should_bypass_check("rate_limit", route_config)
        assert result is False

    def test_get_cloud_providers_from_route_config(
        self, resolver: RouteConfigResolver
    ) -> None:
        """Test get_cloud_providers_to_check from route config."""
        route_config = RouteConfig()
        route_config.block_cloud_providers = {"azure", "digitalocean"}

        result = resolver.get_cloud_providers_to_check(route_config)
        assert result == ["azure", "digitalocean"] or result == [
            "digitalocean",
            "azure",
        ]
        assert set(result) == {"azure", "digitalocean"}

    def test_get_cloud_providers_from_global_config(
        self, resolver: RouteConfigResolver
    ) -> None:
        """Test get_cloud_providers_to_check from global config."""
        route_config = RouteConfig()
        # No block_cloud_providers set

        result = resolver.get_cloud_providers_to_check(route_config)
        assert result == ["aws", "gcp"] or result == ["gcp", "aws"]
        assert set(result) == {"aws", "gcp"}

    def test_get_cloud_providers_none_when_no_config(
        self, resolver: RouteConfigResolver
    ) -> None:
        """Test get_cloud_providers_to_check with no route config."""
        result = resolver.get_cloud_providers_to_check(None)
        assert result == ["aws", "gcp"] or result == ["gcp", "aws"]
        assert set(result) == {"aws", "gcp"}

    def test_get_cloud_providers_none_when_empty(self) -> None:
        """Test get_cloud_providers_to_check when both configs are empty."""
        config = Mock()
        config.block_cloud_providers = set()
        context = RoutingContext(config=config, logger=Mock(), guard_decorator=None)
        resolver = RouteConfigResolver(context)

        result = resolver.get_cloud_providers_to_check(None)
        assert result is None
