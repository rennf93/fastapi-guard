from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import FastAPI, Request, Response

from guard import SecurityConfig, SecurityDecorator
from guard.decorators.base import RouteConfig
from guard.handlers.behavior_handler import BehaviorRule
from guard.handlers.ratelimit_handler import RateLimitManager
from guard.middleware import SecurityMiddleware


async def test_set_decorator_handler() -> None:
    """Test set_decorator_handler method."""
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    decorator = SecurityDecorator(config)
    middleware.set_decorator_handler(decorator)

    assert middleware.guard_decorator is decorator

    middleware.set_decorator_handler(None)
    assert middleware.guard_decorator is None


async def test_get_endpoint_id_with_route() -> None:
    """Test _get_endpoint_id method with route in scope."""
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    mock_request = Mock()
    mock_request.scope = {
        "route": Mock(
            endpoint=Mock(__module__="test_module", __qualname__="test_function")
        )
    }
    mock_request.method = "GET"
    mock_request.url.path = "/test"

    endpoint_id = middleware._get_endpoint_id(mock_request)
    assert endpoint_id == "test_module.test_function"

    mock_request.scope = {}
    endpoint_id = middleware._get_endpoint_id(mock_request)
    assert endpoint_id == "GET:/test"


async def test_should_bypass_check() -> None:
    """Test _should_bypass_check method."""
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    assert not middleware._should_bypass_check("ip", None)

    mock_route_config = Mock()
    mock_route_config.bypassed_checks = {"ip"}
    assert middleware._should_bypass_check("ip", mock_route_config)
    assert not middleware._should_bypass_check("rate_limit", mock_route_config)

    mock_route_config.bypassed_checks = {"all"}
    assert middleware._should_bypass_check("ip", mock_route_config)
    assert middleware._should_bypass_check("rate_limit", mock_route_config)


async def test_check_route_ip_access_invalid_ip() -> None:
    """Test _check_route_ip_access with invalid IP."""
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    mock_route_config = Mock()
    mock_route_config.ip_blacklist = None
    mock_route_config.ip_whitelist = None
    mock_route_config.blocked_countries = None
    mock_route_config.whitelist_countries = None

    result = await middleware._check_route_ip_access("invalid_ip", mock_route_config)
    assert result is False


async def test_check_route_ip_access_blacklist() -> None:
    """Test _check_route_ip_access with IP blacklist."""
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    mock_route_config = Mock()
    mock_route_config.ip_blacklist = ["192.168.1.100", "10.0.0.0/8"]
    mock_route_config.ip_whitelist = None
    mock_route_config.blocked_countries = None
    mock_route_config.whitelist_countries = None

    # Test blocked IP
    result = await middleware._check_route_ip_access("192.168.1.100", mock_route_config)
    assert result is False

    # Test blocked CIDR
    result = await middleware._check_route_ip_access("10.0.0.1", mock_route_config)
    assert result is False

    # Test allowed IP
    result = await middleware._check_route_ip_access("8.8.8.8", mock_route_config)
    assert result is None


async def test_check_route_ip_access_whitelist() -> None:
    """Test _check_route_ip_access with IP whitelist."""
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    mock_route_config = Mock()
    mock_route_config.ip_blacklist = None
    mock_route_config.ip_whitelist = ["192.168.1.100", "10.0.0.0/8"]
    mock_route_config.blocked_countries = None
    mock_route_config.whitelist_countries = None

    # Test allowed IP
    result = await middleware._check_route_ip_access("192.168.1.100", mock_route_config)
    assert result is True

    # Test allowed CIDR
    result = await middleware._check_route_ip_access("10.0.0.1", mock_route_config)
    assert result is True

    # Test blocked IP (not in whitelist)
    result = await middleware._check_route_ip_access("8.8.8.8", mock_route_config)
    assert result is False


async def test_check_route_ip_access_countries() -> None:
    """Test _check_route_ip_access with country restrictions."""
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    # Mock geo IP handler
    mock_geo_handler = Mock()
    middleware.geo_ip_handler = mock_geo_handler

    mock_route_config = Mock()
    mock_route_config.ip_blacklist = None
    mock_route_config.ip_whitelist = None

    # Test blocked countries
    mock_route_config.blocked_countries = ["XX"]
    mock_route_config.whitelist_countries = None
    mock_geo_handler.get_country.return_value = "XX"

    result = await middleware._check_route_ip_access("8.8.8.8", mock_route_config)
    assert result is False

    # Test allowed countries
    mock_route_config.blocked_countries = None
    mock_route_config.whitelist_countries = ["US"]
    mock_geo_handler.get_country.return_value = "US"

    result = await middleware._check_route_ip_access("8.8.8.8", mock_route_config)
    assert result is True

    # Test country not in allowed list
    mock_geo_handler.get_country.return_value = "XX"
    result = await middleware._check_route_ip_access("8.8.8.8", mock_route_config)
    assert result is False

    # Test no country data
    mock_geo_handler.get_country.return_value = None
    result = await middleware._check_route_ip_access("8.8.8.8", mock_route_config)
    assert result is False


async def test_check_user_agent_allowed() -> None:
    """Test _check_user_agent_allowed method."""
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    # Test with route config blocking user agents
    mock_route_config = Mock()
    mock_route_config.blocked_user_agents = [r"badbot"]

    with patch("guard.utils.is_user_agent_allowed", return_value=True):
        result = await middleware._check_user_agent_allowed("badbot", mock_route_config)
        assert result is False

        result = await middleware._check_user_agent_allowed(
            "goodbot", mock_route_config
        )
        assert result is True

    # Test without route config
    with patch("guard.utils.is_user_agent_allowed", return_value=False) as mock_global:
        result = await middleware._check_user_agent_allowed("somebot", None)
        assert result is False
        mock_global.assert_called_once()


async def test_time_window_error_handling() -> None:
    """Test time window check error handling."""
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    # Test with invalid time restrictions
    invalid_time_restrictions = {"invalid": "data"}

    with patch.object(middleware.logger, "error") as mock_error:
        result = await middleware._check_time_window(invalid_time_restrictions)
        assert result is True
        mock_error.assert_called_once()


async def test_time_window_overnight() -> None:
    """Test time window check with overnight window."""
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    time_restrictions = {"start": "22:00", "end": "06:00"}

    # Test time within overnight window (after start)
    with patch("guard.middleware.datetime") as mock_datetime:
        mock_datetime.now.return_value.strftime.return_value = "23:00"
        result = await middleware._check_time_window(time_restrictions)
        assert result is True

    # Test time within overnight window (before end)
    with patch("guard.middleware.datetime") as mock_datetime:
        mock_datetime.now.return_value.strftime.return_value = "05:00"
        result = await middleware._check_time_window(time_restrictions)
        assert result is True

    # Test time outside overnight window
    with patch("guard.middleware.datetime") as mock_datetime:
        mock_datetime.now.return_value.strftime.return_value = "12:00"
        result = await middleware._check_time_window(time_restrictions)
        assert result is False


async def test_time_window_normal() -> None:
    """Test time window check with normal window."""
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    time_restrictions = {"start": "09:00", "end": "17:00"}

    # Test time within normal window
    with patch("guard.middleware.datetime") as mock_datetime:
        mock_datetime.now.return_value.strftime.return_value = "12:00"
        result = await middleware._check_time_window(time_restrictions)
        assert result is True

    # Test time outside normal window
    with patch("guard.middleware.datetime") as mock_datetime:
        mock_datetime.now.return_value.strftime.return_value = "20:00"
        result = await middleware._check_time_window(time_restrictions)
        assert result is False


async def test_behavioral_rules_without_guard_decorator() -> None:
    """Test behavioral rule processing when guard_decorator is None."""
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    # Ensure guard_decorator is None
    middleware.guard_decorator = None

    mock_request = Mock()
    mock_route_config = Mock()
    mock_route_config.behavior_rules = [BehaviorRule("usage", threshold=5, window=3600)]

    # Should not raise any errors and return without processing
    await middleware._process_decorator_usage_rules(
        mock_request, "127.0.0.1", mock_route_config
    )
    await middleware._process_decorator_return_rules(
        mock_request, Mock(), "127.0.0.1", mock_route_config
    )


async def test_behavioral_usage_rules_with_decorator() -> None:
    """Test behavioral usage rule processing with guard decorator."""
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    # Mock guard decorator with behavior tracker
    mock_guard_decorator = Mock()
    mock_behavior_tracker = Mock()
    mock_guard_decorator.behavior_tracker = mock_behavior_tracker
    middleware.guard_decorator = mock_guard_decorator

    mock_request = Mock()
    mock_request.scope = {
        "route": Mock(endpoint=Mock(__module__="test", __qualname__="test_func"))
    }
    mock_request.method = "GET"
    mock_request.url.path = "/test"

    mock_route_config = Mock()
    usage_rule = BehaviorRule("usage", threshold=5, window=3600)
    mock_route_config.behavior_rules = [usage_rule]

    # Test when threshold not exceeded
    async def mock_track_usage(*args: Any, **kwargs: Any) -> bool:
        return False

    mock_behavior_tracker.track_endpoint_usage = mock_track_usage

    await middleware._process_decorator_usage_rules(
        mock_request, "127.0.0.1", mock_route_config
    )
    mock_behavior_tracker.apply_action.assert_not_called()

    # Test when threshold exceeded
    async def mock_track_usage_exceeded(*args: Any, **kwargs: Any) -> bool:
        return True

    async def mock_apply_action(*args: Any, **kwargs: Any) -> None:
        return None

    mock_behavior_tracker.track_endpoint_usage = mock_track_usage_exceeded
    mock_behavior_tracker.apply_action = mock_apply_action

    await middleware._process_decorator_usage_rules(
        mock_request, "127.0.0.1", mock_route_config
    )


async def test_behavioral_return_rules_with_decorator() -> None:
    """Test behavioral return rule processing with guard decorator."""
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    # Mock guard decorator with behavior tracker
    mock_guard_decorator = Mock()
    mock_behavior_tracker = Mock()
    mock_guard_decorator.behavior_tracker = mock_behavior_tracker
    middleware.guard_decorator = mock_guard_decorator

    mock_request = Mock()
    mock_request.scope = {
        "route": Mock(endpoint=Mock(__module__="test", __qualname__="test_func"))
    }
    mock_request.method = "GET"
    mock_request.url.path = "/test"

    mock_response = Mock()
    mock_route_config = Mock()
    return_rule = BehaviorRule(
        "return_pattern", threshold=3, window=3600, pattern="win"
    )
    mock_route_config.behavior_rules = [return_rule]

    # Test when pattern not detected
    async def mock_track_pattern(*args: Any, **kwargs: Any) -> bool:
        return False

    mock_behavior_tracker.track_return_pattern = mock_track_pattern

    await middleware._process_decorator_return_rules(
        mock_request, mock_response, "127.0.0.1", mock_route_config
    )
    mock_behavior_tracker.apply_action.assert_not_called()

    # Test when pattern detected
    async def mock_track_pattern_detected(*args: Any, **kwargs: Any) -> bool:
        return True

    async def mock_apply_action(*args: Any, **kwargs: Any) -> None:
        return None

    mock_behavior_tracker.track_return_pattern = mock_track_pattern_detected
    mock_behavior_tracker.apply_action = mock_apply_action

    await middleware._process_decorator_return_rules(
        mock_request, mock_response, "127.0.0.1", mock_route_config
    )


async def test_get_route_decorator_config_no_app() -> None:
    """Test _get_route_decorator_config when no app in scope."""
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    mock_request = Mock()
    mock_request.scope = {}  # No app in scope

    result = middleware._get_route_decorator_config(mock_request)
    assert result is None


async def test_get_route_decorator_config_no_guard_decorator() -> None:
    """Test _get_route_decorator_config when no guard decorator available."""
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    mock_request = Mock()
    mock_app = Mock()
    mock_app.state = Mock()
    mock_request.scope = {"app": mock_app}

    result = middleware._get_route_decorator_config(mock_request)
    assert result is None


async def test_get_route_decorator_config_fallback_to_middleware_decorator() -> None:
    """Test _get_route_decorator_config falls back to middleware guard_decorator."""
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    decorator = SecurityDecorator(config)
    middleware.guard_decorator = decorator

    mock_request = Mock()
    mock_request.url = Mock()
    mock_request.url.path = "/test"
    mock_request.method = "GET"

    # App exists but state doesn't have guard_decorator
    mock_app = Mock()
    mock_app.state = Mock(spec=[])
    mock_app.routes = []
    mock_request.scope = {"app": mock_app}

    result = middleware._get_route_decorator_config(mock_request)
    assert result is None


async def test_get_route_decorator_config_no_matching_route() -> None:
    """Test _get_route_decorator_config when no matching route is found."""
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    decorator = SecurityDecorator(config)

    mock_request = Mock()
    mock_request.url.path = "/nonexistent"
    mock_request.method = "GET"

    mock_app = Mock()
    mock_app.routes = []
    mock_app.state = Mock()
    mock_app.state.guard_decorator = decorator
    mock_request.scope = {"app": mock_app}

    result = middleware._get_route_decorator_config(mock_request)
    assert result is None


async def test_bypass_all_security_checks() -> None:
    """Test bypassing all security checks when 'all' is in bypassed_checks."""
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    mock_route_config = RouteConfig()
    mock_route_config.bypassed_checks = {"all"}

    mock_request = Mock()
    mock_request.client.host = "127.0.0.1"
    mock_request.url.scheme = "http"
    mock_request.url.path = "/test"
    mock_request.headers = {}

    async def mock_call_next(request: Request) -> Response:
        return Response("bypassed", status_code=200)

    with patch.object(
        middleware, "_get_route_decorator_config", return_value=mock_route_config
    ):
        response = await middleware.dispatch(mock_request, mock_call_next)
        assert response.status_code == 200


async def test_bypass_all_security_checks_with_custom_modifier() -> None:
    """Test bypassing all security checks with custom response modifier."""
    app = FastAPI()

    async def custom_modifier(response: Response) -> Response:
        modified_response = Response("custom modified", status_code=202)
        return modified_response

    config = SecurityConfig(custom_response_modifier=custom_modifier)
    middleware = SecurityMiddleware(app, config=config)

    mock_route_config = RouteConfig()
    mock_route_config.bypassed_checks = {"all"}

    mock_request = Mock()
    mock_request.client.host = "127.0.0.1"
    mock_request.url.scheme = "http"
    mock_request.url.path = "/test"
    mock_request.headers = {}

    async def mock_call_next(request: Request) -> Response:
        return Response("bypassed", status_code=200)

    with patch.object(
        middleware, "_get_route_decorator_config", return_value=mock_route_config
    ):
        response = await middleware.dispatch(mock_request, mock_call_next)
        assert response.status_code == 202
        assert response.body == b"custom modified"


@pytest.mark.parametrize(
    "test_case,expected_status,description",
    [
        (
            {"max_request_size": 100, "headers": {"content-length": "200"}},
            413,
            "Test route-specific request size limits",
        ),
        (
            {
                "allowed_content_types": ["application/json"],
                "headers": {"content-type": "text/plain"},
            },
            415,
            "Test route-specific content type filtering",
        ),
        (
            {
                "custom_validators": [
                    AsyncMock(
                        return_value=Response(
                            "Custom validation failed", status_code=400
                        )
                    )
                ],
                "headers": {},
            },
            400,
            "Test custom validator returning a Response object",
        ),
        (
            {"custom_validators": [AsyncMock(return_value=None)], "headers": {}},
            200,
            "Test custom validator returning None (allows request to proceed)",
        ),
    ],
)
async def test_route_specific_middleware_validations(
    test_case: dict, expected_status: int, description: str
) -> None:
    """Parametrized test for route-specific middleware validation features."""
    app = FastAPI()
    config = SecurityConfig()
    middleware = SecurityMiddleware(app, config=config)

    mock_route_config = RouteConfig()

    # Set up route config based on test case
    for attr, value in test_case.items():
        if attr != "headers":
            setattr(mock_route_config, attr, value)

    mock_request = Mock()
    mock_request.client.host = "127.0.0.1"
    mock_request.url.scheme = "http"
    mock_request.url.path = "/test"
    mock_request.headers = test_case["headers"]
    mock_request.query_params = {}

    async def mock_call_next(request: Request) -> Response:
        return Response("ok", status_code=200)

    with patch.object(
        middleware, "_get_route_decorator_config", return_value=mock_route_config
    ):
        with patch("guard.utils.detect_penetration_attempt", return_value=(False, "")):
            response = await middleware.dispatch(mock_request, mock_call_next)
            assert response.status_code == expected_status


async def test_route_specific_rate_limit_with_redis() -> None:
    """Test route-specific rate limiting with Redis initialization."""
    app = FastAPI()
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    middleware = SecurityMiddleware(app, config=config)

    # Mock Redis handler
    mock_redis_handler = Mock()
    middleware.redis_handler = mock_redis_handler

    # Mock route config with rate limit
    mock_route_config = RouteConfig()
    mock_route_config.rate_limit = 5
    mock_route_config.rate_limit_window = 60

    mock_request = Mock()
    mock_request.client.host = "127.0.0.1"
    mock_request.url.scheme = "http"
    mock_request.url.path = "/test"
    mock_request.headers = {}
    mock_request.query_params = {}

    async def mock_call_next(request: Request) -> Response:
        return Response("ok", status_code=200)

    with patch.object(
        middleware, "_get_route_decorator_config", return_value=mock_route_config
    ):
        with patch.object(RateLimitManager, "initialize_redis") as mock_init_redis:
            with patch.object(RateLimitManager, "check_rate_limit", return_value=None):
                with patch(
                    "guard.utils.detect_penetration_attempt", return_value=(False, "")
                ):
                    await middleware.dispatch(mock_request, mock_call_next)
                    mock_init_redis.assert_called_once_with(mock_redis_handler)
