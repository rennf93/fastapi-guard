from unittest.mock import Mock

import pytest
from fastapi import FastAPI, Request, Response
from fastapi.routing import APIRoute
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport

from guard import SecurityConfig, SecurityDecorator
from guard.middleware import SecurityMiddleware


@pytest.fixture
async def content_decorator_app(security_config: SecurityConfig) -> FastAPI:
    """Create FastAPI app with content filtering decorator integration."""
    app = FastAPI()

    security_config.trusted_proxies = ["127.0.0.1"]
    security_config.enable_penetration_detection = False

    decorator = SecurityDecorator(security_config)

    @decorator.block_user_agents(["bot", "crawler"])
    @app.get("/block-agents")
    async def block_agents_endpoint() -> dict[str, str]:
        return {"message": "User agent allowed"}

    @decorator.content_type_filter(["application/json", "text/plain"])
    @app.post("/content-filter")
    async def content_filter_endpoint() -> dict[str, str]:
        return {"message": "Content type allowed"}

    @decorator.max_request_size(1024)
    @app.post("/size-limit")
    async def size_limit_endpoint() -> dict[str, str]:
        return {"message": "Request size within limit"}

    @decorator.require_referrer(["example.com", "app.example.com"])
    @app.get("/referrer-check")
    async def referrer_check_endpoint() -> dict[str, str]:
        return {"message": "Referrer validated"}

    async def custom_validator_func(request: Request) -> Response | None:
        if "forbidden" in str(request.url):
            return Response(
                content="Custom validation failed", status_code=400
            )  # pragma: no cover
        return None

    @decorator.custom_validation(custom_validator_func)
    @app.get("/custom-validation")
    async def custom_validation_endpoint() -> dict[str, str]:
        return {"message": "Custom validation passed"}

    app.add_middleware(SecurityMiddleware, config=security_config)
    app.state.guard_decorator = decorator

    return app


@pytest.mark.parametrize(
    "route_path,expected_attr,expected_value,description",
    [
        (
            "/block-agents",
            "blocked_user_agents",
            ["bot", "crawler"],
            "block_user_agents decorator",
        ),
        (
            "/content-filter",
            "allowed_content_types",
            ["application/json", "text/plain"],
            "content_type_filter decorator",
        ),
        ("/size-limit", "max_request_size", 1024, "max_request_size decorator"),
        (
            "/referrer-check",
            "require_referrer",
            ["example.com", "app.example.com"],
            "require_referrer decorator",
        ),
    ],
)
async def test_content_filtering_decorators_applied(
    content_decorator_app: FastAPI,
    route_path: str,
    expected_attr: str,
    expected_value: list[str] | int,
    description: str,
) -> None:
    """Test that content filtering decorators are applied correctly."""
    for route in content_decorator_app.routes:
        if isinstance(route, APIRoute) and route.path == route_path:
            assert hasattr(route.endpoint, "_guard_route_id"), (
                f"{description} should have route ID"
            )

            decorator = content_decorator_app.state.guard_decorator
            route_id = route.endpoint._guard_route_id
            route_config = decorator.get_route_config(route_id)

            assert route_config is not None, f"{description} should have route config"
            assert getattr(route_config, expected_attr) == expected_value, (
                f"{description} should have correct {expected_attr}"
            )


async def test_custom_validation_decorator_applied(
    content_decorator_app: FastAPI,
) -> None:
    """Test that custom validation decorator is applied correctly."""
    for route in content_decorator_app.routes:
        if isinstance(route, APIRoute) and route.path == "/custom-validation":
            assert hasattr(route.endpoint, "_guard_route_id"), (
                "custom_validation decorator should have route ID"
            )

            decorator = content_decorator_app.state.guard_decorator
            route_id = route.endpoint._guard_route_id
            route_config = decorator.get_route_config(route_id)

            assert route_config is not None, (
                "custom_validation should have route config"
            )
            assert len(route_config.custom_validators) == 1, (
                "custom_validation should have one validator"
            )


@pytest.mark.parametrize(
    "endpoint,expected_message,description",
    [
        ("/block-agents", "User agent allowed", "block_user_agents endpoint"),
        ("/content-filter", "Content type allowed", "content_type_filter endpoint"),
        ("/size-limit", "Request size within limit", "max_request_size endpoint"),
        ("/referrer-check", "Referrer validated", "require_referrer endpoint"),
        (
            "/custom-validation",
            "Custom validation passed",
            "custom_validation endpoint",
        ),
    ],
)
async def test_content_filtering_endpoints_response(
    content_decorator_app: FastAPI,
    endpoint: str,
    expected_message: str,
    description: str,
) -> None:
    """Test calling content filtering endpoints and their responses."""
    async with AsyncClient(
        transport=ASGITransport(app=content_decorator_app), base_url="http://test"
    ) as client:
        method = "post" if endpoint in ["/content-filter", "/size-limit"] else "get"
        headers = {"X-Forwarded-For": "8.8.8.8"}

        if endpoint == "/content-filter":
            headers["Content-Type"] = "application/json"
            response = await getattr(client, method)(
                endpoint, headers=headers, json={"test": "data"}
            )
        elif endpoint == "/size-limit":
            headers["Content-Type"] = "text/plain"
            response = await getattr(client, method)(
                endpoint, headers=headers, content="small data"
            )
        elif endpoint == "/referrer-check":
            headers["Referer"] = "https://example.com/page"
            response = await getattr(client, method)(endpoint, headers=headers)
        else:
            response = await getattr(client, method)(endpoint, headers=headers)

        assert response.status_code == 200, f"{description} should return 200"
        assert expected_message in response.text, (
            f"{description} should contain '{expected_message}'"
        )


async def test_content_filtering_decorators_unit(
    security_config: SecurityConfig,
) -> None:
    """Unit tests for content filtering decorators."""
    decorator = SecurityDecorator(security_config)

    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    # Test block_user_agents
    user_agent_decorator = decorator.block_user_agents(["bot", "spider"])
    decorated_func = user_agent_decorator(mock_func)

    route_id = decorated_func._guard_route_id  # type: ignore[attr-defined]
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    assert route_config.blocked_user_agents == ["bot", "spider"]

    # Test content_type_filter
    mock_func2 = Mock()
    mock_func2.__name__ = mock_func2.__qualname__ = "test_func2"
    mock_func2.__module__ = "test_module"

    content_type_decorator = decorator.content_type_filter(["application/json"])
    decorated_func2 = content_type_decorator(mock_func2)

    route_id2 = decorated_func2._guard_route_id  # type: ignore[attr-defined]
    route_config2 = decorator.get_route_config(route_id2)
    assert route_config2 is not None
    assert route_config2.allowed_content_types == ["application/json"]

    # Test max_request_size
    mock_func3 = Mock()
    mock_func3.__name__ = mock_func3.__qualname__ = "test_func3"
    mock_func3.__module__ = "test_module"

    size_decorator = decorator.max_request_size(2048)
    decorated_func3 = size_decorator(mock_func3)

    route_id3 = decorated_func3._guard_route_id  # type: ignore[attr-defined]
    route_config3 = decorator.get_route_config(route_id3)
    assert route_config3 is not None
    assert route_config3.max_request_size == 2048

    # Test require_referrer
    mock_func4 = Mock()
    mock_func4.__name__ = mock_func4.__qualname__ = "test_func4"
    mock_func4.__module__ = "test_module"

    referrer_decorator = decorator.require_referrer(["example.com"])
    decorated_func4 = referrer_decorator(mock_func4)

    route_id4 = decorated_func4._guard_route_id  # type: ignore[attr-defined]
    route_config4 = decorator.get_route_config(route_id4)
    assert route_config4 is not None
    assert route_config4.require_referrer == ["example.com"]

    # Test custom_validation
    mock_func5 = Mock()
    mock_func5.__name__ = mock_func5.__qualname__ = "test_func5"
    mock_func5.__module__ = "test_module"

    async def test_validator(request: Request) -> Response | None:
        return None

    custom_decorator = decorator.custom_validation(test_validator)
    decorated_func5 = custom_decorator(mock_func5)

    route_id5 = decorated_func5._guard_route_id  # type: ignore[attr-defined]
    route_config5 = decorator.get_route_config(route_id5)
    assert route_config5 is not None
    assert len(route_config5.custom_validators) == 1
    assert route_config5.custom_validators[0] == test_validator

    # Test that the validator returns None
    result = await test_validator(Mock())
    assert result is None
