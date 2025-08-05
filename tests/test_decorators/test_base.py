from unittest.mock import Mock

import pytest
from fastapi import Request

from guard import SecurityConfig
from guard.decorators.base import (
    BaseSecurityDecorator,
    BaseSecurityMixin,
    RouteConfig,
    get_route_decorator_config,
)


async def test_route_config_initialization() -> None:
    """Test RouteConfig initialization with default values."""
    config = RouteConfig()

    # Test all default values
    assert config.rate_limit is None
    assert config.rate_limit_window is None
    assert config.ip_whitelist is None
    assert config.ip_blacklist is None
    assert config.blocked_countries is None
    assert config.whitelist_countries is None
    assert config.bypassed_checks == set()
    assert config.require_https is False
    assert config.auth_required is None
    assert config.custom_validators == []
    assert config.blocked_user_agents == []
    assert config.required_headers == {}
    assert config.behavior_rules == []
    assert config.block_cloud_providers == set()
    assert config.max_request_size is None
    assert config.allowed_content_types is None
    assert config.time_restrictions is None
    assert config.enable_suspicious_detection is True
    assert config.require_referrer is None
    assert config.api_key_required is False
    assert config.session_limits is None


async def test_base_security_mixin_not_implemented() -> None:
    """Test BaseSecurityMixin raises NotImplementedError for abstract methods."""
    mixin = BaseSecurityMixin()

    mock_func = Mock()

    # Test _ensure_route_config raises NotImplementedError
    with pytest.raises(
        NotImplementedError, match="This mixin must be used with BaseSecurityDecorator"
    ):
        mixin._ensure_route_config(mock_func)

    # Test _apply_route_config raises NotImplementedError
    with pytest.raises(
        NotImplementedError, match="This mixin must be used with BaseSecurityDecorator"
    ):
        mixin._apply_route_config(mock_func)


async def test_base_security_decorator(security_config: SecurityConfig) -> None:
    """Test BaseSecurityDecorator functionality."""
    decorator = BaseSecurityDecorator(security_config)

    # Test initialization
    assert decorator.config == security_config
    assert decorator._route_configs == {}
    assert decorator.behavior_tracker is not None

    # Test _get_route_id
    mock_func = Mock()
    mock_func.__module__ = "test_module"
    mock_func.__qualname__ = "test_function"

    route_id = decorator._get_route_id(mock_func)
    assert route_id == "test_module.test_function"

    # Test _ensure_route_config creates new config
    route_config = decorator._ensure_route_config(mock_func)
    assert isinstance(route_config, RouteConfig)
    assert (
        route_config.enable_suspicious_detection
        == security_config.enable_penetration_detection
    )

    # Test _ensure_route_config returns existing config
    route_config2 = decorator._ensure_route_config(mock_func)
    assert route_config is route_config2  # Same instance

    # Test get_route_config
    retrieved_config = decorator.get_route_config(route_id)
    assert retrieved_config is route_config

    # Test get_route_config with non-existent route
    non_existent_config = decorator.get_route_config("non.existent.route")
    assert non_existent_config is None

    # Test _apply_route_config
    decorated_func = decorator._apply_route_config(mock_func)
    assert decorated_func is mock_func
    assert hasattr(decorated_func, "_guard_route_id")
    assert decorated_func._guard_route_id == route_id


async def test_get_route_decorator_config() -> None:
    """Test get_route_decorator_config function."""
    security_config = SecurityConfig()
    decorator = BaseSecurityDecorator(security_config)

    # Test with request that has no route
    mock_request = Mock(spec=Request)
    mock_request.scope = {}

    result = get_route_decorator_config(mock_request, decorator)
    assert result is None

    # Test with request that has route but no endpoint
    mock_request.scope = {"route": Mock()}
    mock_request.scope["route"].endpoint = None

    result = get_route_decorator_config(mock_request, decorator)
    assert result is None

    # Test with request that has route and endpoint but no _guard_route_id
    mock_endpoint = Mock()
    mock_request.scope["route"].endpoint = mock_endpoint

    result = get_route_decorator_config(mock_request, decorator)
    assert result is None

    # Test with complete route configuration
    route_id = "test.route.id"
    mock_endpoint._guard_route_id = route_id

    # Create a route config for this route
    route_config = decorator._ensure_route_config(
        Mock(__module__="test", __qualname__="route")
    )
    decorator._route_configs[route_id] = route_config

    result = get_route_decorator_config(mock_request, decorator)
    assert result is route_config


async def test_initialize_behavior_tracking(security_config: SecurityConfig) -> None:
    """Test initialize_behavior_tracking method."""
    decorator = BaseSecurityDecorator(security_config)

    # Test without redis handler
    await decorator.initialize_behavior_tracking()

    # Test with redis handler
    mock_redis_handler = Mock()
    await decorator.initialize_behavior_tracking(mock_redis_handler)
