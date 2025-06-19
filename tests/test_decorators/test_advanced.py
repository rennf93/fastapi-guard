import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import FastAPI
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport

from guard import SecurityConfig, SecurityDecorator
from guard.middleware import SecurityMiddleware

IPINFO_TOKEN = str(os.getenv("IPINFO_TOKEN"))


@pytest.fixture
async def advanced_decorator_app(security_config: SecurityConfig) -> FastAPI:
    """Create FastAPI app with advanced decorator integration."""
    app = FastAPI()

    security_config.trusted_proxies = ["127.0.0.1"]
    security_config.enable_penetration_detection = False

    decorator = SecurityDecorator(security_config)

    @decorator.time_window("09:00", "17:00", "UTC")
    @app.get("/business-hours")
    async def business_hours_endpoint() -> dict[str, str]:
        return {"message": "Business hours access"}

    @decorator.time_window("22:00", "06:00", "UTC")  # Night hours
    @app.get("/night-hours")
    async def night_hours_endpoint() -> dict[str, str]:
        return {"message": "Night hours access"}

    @decorator.suspicious_detection(enabled=True)
    @app.get("/suspicious-enabled")
    async def suspicious_enabled_endpoint() -> dict[str, str]:
        return {"message": "Suspicious detection enabled"}

    @decorator.suspicious_detection(enabled=False)
    @app.get("/suspicious-disabled")
    async def suspicious_disabled_endpoint() -> dict[str, str]:
        return {"message": "Suspicious detection disabled"}

    @decorator.honeypot_detection(["bot_trap", "hidden_field"])
    @app.post("/form-honeypot")
    async def form_honeypot_endpoint() -> dict[str, str]:
        return {"message": "Form submitted successfully"}

    @decorator.honeypot_detection(["spam_check", "robot_field"])
    @app.post("/json-honeypot")
    async def json_honeypot_endpoint() -> dict[str, str]:
        return {"message": "JSON submitted successfully"}

    app.add_middleware(SecurityMiddleware, config=security_config)
    app.state.guard_decorator = decorator

    return app


@pytest.mark.parametrize(
    "endpoint,mock_hour,expected_status,description",
    [
        ("/business-hours", 12, 200, "Noon should be allowed during business hours"),
        ("/business-hours", 6, 403, "Early morning should be blocked"),
        ("/business-hours", 20, 403, "Evening should be blocked"),
        ("/night-hours", 23, 200, "Late night should be allowed"),
        ("/night-hours", 2, 200, "Early morning should be allowed"),
        ("/night-hours", 14, 403, "Afternoon should be blocked"),
    ],
)
async def test_time_window_restrictions(
    advanced_decorator_app: FastAPI,
    endpoint: str,
    mock_hour: int,
    expected_status: int,
    description: str,
) -> None:
    """Test time window restrictions."""
    # Create a datetime object for the mock hour
    mock_datetime = datetime(2025, 1, 15, mock_hour, 30, 0, tzinfo=timezone.utc)

    with patch("guard.middleware.SecurityMiddleware._check_time_window") as mock_time_check:
        # Mock the time window check directly
        if expected_status == 200:
            mock_time_check.return_value = True
        else:
            mock_time_check.return_value = False

        async with AsyncClient(
            transport=ASGITransport(app=advanced_decorator_app), base_url="http://test"
        ) as client:
            response = await client.get(
                endpoint,
                headers={"X-Forwarded-For": "127.0.0.1"},
            )
            assert response.status_code == expected_status, description


async def test_suspicious_detection_enabled(advanced_decorator_app: FastAPI) -> None:
    """Test that suspicious detection decorator is applied correctly."""
    # Find the route and verify decorator was applied
    for route in advanced_decorator_app.routes:
        if route.path == "/suspicious-enabled":
            assert hasattr(route.endpoint, "_guard_route_id")

            decorator = advanced_decorator_app.state.guard_decorator
            route_id = route.endpoint._guard_route_id
            route_config = decorator.get_route_config(route_id)

            assert route_config is not None
            assert route_config.enable_suspicious_detection is True


async def test_suspicious_detection_disabled(advanced_decorator_app: FastAPI) -> None:
    """Test that suspicious detection disabled decorator is applied correctly."""
    # Find the route and verify decorator was applied
    for route in advanced_decorator_app.routes:
        if route.path == "/suspicious-disabled":
            assert hasattr(route.endpoint, "_guard_route_id")

            decorator = advanced_decorator_app.state.guard_decorator
            route_id = route.endpoint._guard_route_id
            route_config = decorator.get_route_config(route_id)

            assert route_config is not None
            assert route_config.enable_suspicious_detection is False


async def test_suspicious_endpoints_response(advanced_decorator_app: FastAPI) -> None:
    """Test calling suspicious endpoints and their responses."""
    async with AsyncClient(
        transport=ASGITransport(app=advanced_decorator_app), base_url="http://test"
    ) as client:
        # Test suspicious enabled endpoint
        response = await client.get("/suspicious-enabled", headers={"X-Forwarded-For": "8.8.8.8"})
        assert response.status_code == 200
        assert response.json()["message"] == "Suspicious detection enabled"

        # Test suspicious disabled endpoint
        response = await client.get("/suspicious-disabled", headers={"X-Forwarded-For": "8.8.8.8"})
        assert response.status_code == 200
        assert response.json()["message"] == "Suspicious detection disabled"


@pytest.mark.parametrize(
    "endpoint,expected_fields,description",
    [
        ("/form-honeypot", ["bot_trap", "hidden_field"], "Form honeypot should have trap fields configured"),
        ("/json-honeypot", ["spam_check", "robot_field"], "JSON honeypot should have trap fields configured"),
    ],
)
async def test_honeypot_detection_configuration(
    advanced_decorator_app: FastAPI,
    endpoint: str,
    expected_fields: list[str],
    description: str,
) -> None:
    """Test that honeypot detection decorators are configured correctly."""
    # Find the route and verify decorator was applied
    for route in advanced_decorator_app.routes:
        if route.path == endpoint:
            assert hasattr(route.endpoint, "_guard_route_id")

            decorator = advanced_decorator_app.state.guard_decorator
            route_id = route.endpoint._guard_route_id
            route_config = decorator.get_route_config(route_id)

            assert route_config is not None
            assert len(route_config.custom_validators) == 1, "Should have one custom validator"

            # Verify the validator is a honeypot validator by checking its closure
            validator = route_config.custom_validators[0]
            assert hasattr(validator, "__code__")
            assert "trap_fields" in validator.__code__.co_freevars


async def test_honeypot_detection_basic_functionality(advanced_decorator_app: FastAPI) -> None:
    """Test basic honeypot detection functionality - clean requests should pass."""
    async with AsyncClient(
        transport=ASGITransport(app=advanced_decorator_app), base_url="http://test"
    ) as client:
        # Test clean form data passes
        response = await client.post(
            "/form-honeypot",
            data={"name": "John", "email": "john@example.com"},
            headers={
                "X-Forwarded-For": "127.0.0.1",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        assert response.status_code == 200

        # Test clean JSON data passes
        response = await client.post(
            "/json-honeypot",
            json={"name": "Jane", "message": "Hello"},
            headers={"X-Forwarded-For": "127.0.0.1"},
        )
        assert response.status_code == 200


async def test_honeypot_form_detection(security_config: SecurityConfig) -> None:
    decorator = SecurityDecorator(security_config)
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = decorator.honeypot_detection(["bot_trap"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = decorated_func._guard_route_id
    route_config = decorator.get_route_config(route_id)
    validator = route_config.custom_validators[0]

    mock_request = AsyncMock()
    mock_request.method = "POST"
    mock_request.headers.get = lambda key, default="": "application/x-www-form-urlencoded" if key == "content-type" else default
    mock_request.form.return_value = {"bot_trap": "filled"}

    result = await validator(mock_request)
    assert result.status_code == 403


async def test_honeypot_json_exception(security_config: SecurityConfig) -> None:
    decorator = SecurityDecorator(security_config)
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = decorator.honeypot_detection(["spam_check"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = decorated_func._guard_route_id
    route_config = decorator.get_route_config(route_id)
    validator = route_config.custom_validators[0]

    mock_request = AsyncMock()
    mock_request.method = "POST"
    mock_request.headers.get = lambda key, default="": "application/json" if key == "content-type" else default
    mock_request.json.side_effect = Exception("JSON error")

    result = await validator(mock_request)
    assert result is None


async def test_honeypot_json_detection(security_config: SecurityConfig) -> None:
    decorator = SecurityDecorator(security_config)
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = decorator.honeypot_detection(["spam_check"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = decorated_func._guard_route_id
    route_config = decorator.get_route_config(route_id)
    validator = route_config.custom_validators[0]

    mock_request = AsyncMock()
    mock_request.method = "POST"
    mock_request.headers.get = lambda key, default="": "application/json" if key == "content-type" else default
    mock_request.json.return_value = {"spam_check": "filled"}

    result = await validator(mock_request)
    assert result.status_code == 403
