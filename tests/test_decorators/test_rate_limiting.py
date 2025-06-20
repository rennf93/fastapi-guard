from unittest.mock import Mock

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport

from guard import SecurityConfig, SecurityDecorator
from guard.middleware import SecurityMiddleware


@pytest.fixture
async def rate_limiting_decorator_app(security_config: SecurityConfig) -> FastAPI:
    """Create FastAPI app with rate limiting decorator integration."""
    app = FastAPI()

    security_config.trusted_proxies = ["127.0.0.1"]
    security_config.enable_penetration_detection = False

    decorator = SecurityDecorator(security_config)

    @decorator.rate_limit(requests=10, window=60)
    @app.get("/rate-limited")
    async def rate_limited_endpoint() -> dict[str, str]:
        return {"message": "Rate limited endpoint"}

    @decorator.geo_rate_limit({
        "US": (100, 3600),
        "CN": (10, 3600),
        "*": (50, 3600)
    })
    @app.get("/geo-rate-limited")
    async def geo_rate_limited_endpoint() -> dict[str, str]:
        return {"message": "Geo rate limited endpoint"}

    app.add_middleware(SecurityMiddleware, config=security_config)
    app.state.guard_decorator = decorator

    return app


@pytest.mark.parametrize(
    "route_path,expected_rate_limit,expected_window,description",
    [
        ("/rate-limited", 10, 60, "rate_limit decorator"),
    ],
)
async def test_rate_limiting_decorators_applied(
    rate_limiting_decorator_app: FastAPI,
    route_path: str,
    expected_rate_limit: int,
    expected_window: int,
    description: str,
) -> None:
    """Test that rate limiting decorators are applied correctly."""
    for route in rate_limiting_decorator_app.routes:
        if isinstance(route, APIRoute) and route.path == route_path:
            assert hasattr(route.endpoint, "_guard_route_id"), (
                f"{description} should have route ID"
            )

            decorator = rate_limiting_decorator_app.state.guard_decorator
            route_id = route.endpoint._guard_route_id
            route_config = decorator.get_route_config(route_id)

            assert route_config is not None, f"{description} should have route config"
            assert route_config.rate_limit == expected_rate_limit, (
                f"{description} should have correct rate limit"
            )
            assert route_config.rate_limit_window == expected_window, (
                f"{description} should have correct rate limit window"
            )


async def test_geo_rate_limit_decorator_applied(
    rate_limiting_decorator_app: FastAPI,
) -> None:
    """Test that geo rate limit decorator is applied correctly."""
    for route in rate_limiting_decorator_app.routes:
        if isinstance(route, APIRoute) and route.path == "/geo-rate-limited":
            assert hasattr(route.endpoint, "_guard_route_id"), (
                "geo_rate_limit decorator should have route ID"
            )

            decorator = rate_limiting_decorator_app.state.guard_decorator
            route_id = route.endpoint._guard_route_id
            route_config = decorator.get_route_config(route_id)

            assert route_config is not None, (
                "geo_rate_limit should have route config"
            )
            expected_limits = "{'US': (100, 3600), 'CN': (10, 3600), '*': (50, 3600)}"
            assert route_config.required_headers["geo_rate_limits"] == expected_limits, (
                "geo_rate_limit should store limits in required_headers"
            )


@pytest.mark.parametrize(
    "endpoint,expected_message,description",
    [
        ("/rate-limited", "Rate limited endpoint", "rate_limit endpoint"),
        ("/geo-rate-limited", "Geo rate limited endpoint", "geo_rate_limit endpoint"),
    ],
)
async def test_rate_limiting_endpoints_response(
    rate_limiting_decorator_app: FastAPI,
    endpoint: str,
    expected_message: str,
    description: str,
) -> None:
    """Test calling rate limiting endpoints and their responses."""
    async with AsyncClient(
        transport=ASGITransport(app=rate_limiting_decorator_app), base_url="http://test"
    ) as client:
        headers = {"X-Forwarded-For": "8.8.8.8"}

        response = await client.get(endpoint, headers=headers)

        assert response.status_code == 200, f"{description} should return 200"
        assert expected_message in response.text, (
            f"{description} should contain '{expected_message}'"
        )


async def test_rate_limiting_decorators_unit(security_config: SecurityConfig) -> None:
    """Unit tests for rate limiting decorators."""
    decorator = SecurityDecorator(security_config)

    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    # Test rate_limit decorator
    rate_limit_decorator = decorator.rate_limit(requests=5, window=120)
    decorated_func = rate_limit_decorator(mock_func)

    route_id = decorated_func._guard_route_id  # type: ignore[attr-defined]
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    assert route_config.rate_limit == 5
    assert route_config.rate_limit_window == 120

    # Test geo_rate_limit decorator
    mock_func2 = Mock()
    mock_func2.__name__ = mock_func2.__qualname__ = "test_func2"
    mock_func2.__module__ = "test_module"

    limits = {"US": (100, 3600), "EU": (50, 3600)}
    geo_rate_limit_decorator = decorator.geo_rate_limit(limits)
    decorated_func2 = geo_rate_limit_decorator(mock_func2)

    route_id2 = decorated_func2._guard_route_id  # type: ignore[attr-defined]
    route_config2 = decorator.get_route_config(route_id2)
    assert route_config2 is not None
    assert route_config2.required_headers["geo_rate_limits"] == str(limits)