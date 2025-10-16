from unittest.mock import AsyncMock, Mock

import pytest

from guard import SecurityDecorator
from guard.models import SecurityConfig


@pytest.fixture
def security_config() -> SecurityConfig:
    """Create security config."""
    return SecurityConfig()


@pytest.fixture
def decorator(security_config: SecurityConfig) -> SecurityDecorator:
    """Create SecurityDecorator instance."""
    return SecurityDecorator(security_config)


class TestHoneypotEdgeCases:
    """Test honeypot_detection edge cases."""

    async def test_honeypot_form_exception_caught(
        self, decorator: SecurityDecorator
    ) -> None:
        """Test honeypot form validation when form() raises exception."""
        # Lines 94-95: except Exception: pass
        mock_func = Mock()
        mock_func.__name__ = mock_func.__qualname__ = "test_func"
        mock_func.__module__ = "test_module"

        honeypot_decorator = decorator.honeypot_detection(["trap_field"])
        decorated_func = honeypot_decorator(mock_func)

        route_id = decorated_func._guard_route_id  # type: ignore[attr-defined]
        route_config = decorator.get_route_config(route_id)
        assert route_config is not None
        validator = route_config.custom_validators[0]

        # Create request that will cause form() to raise exception
        mock_request = AsyncMock()
        mock_request.method = "POST"
        mock_request.headers.get = (
            lambda key, default="": "application/x-www-form-urlencoded"
            if key == "content-type"
            else default
        )
        mock_request.form.side_effect = Exception("Form parsing error")

        # Should catch exception and return None
        result = await validator(mock_request)
        assert result is None

    async def test_honeypot_non_post_method(self, decorator: SecurityDecorator) -> None:
        """Test honeypot validator with non-POST method."""
        # Line 109: return None when method not in ["POST", "PUT", "PATCH"]
        mock_func = Mock()
        mock_func.__name__ = mock_func.__qualname__ = "test_func"
        mock_func.__module__ = "test_module"

        honeypot_decorator = decorator.honeypot_detection(["trap_field"])
        decorated_func = honeypot_decorator(mock_func)

        route_id = decorated_func._guard_route_id  # type: ignore[attr-defined]
        route_config = decorator.get_route_config(route_id)
        assert route_config is not None
        validator = route_config.custom_validators[0]

        # Test with GET method
        mock_request = AsyncMock()
        mock_request.method = "GET"

        result = await validator(mock_request)
        assert result is None

        # Test with DELETE method
        mock_request.method = "DELETE"
        result = await validator(mock_request)
        assert result is None

    async def test_honeypot_unsupported_content_type(
        self, decorator: SecurityDecorator
    ) -> None:
        """Test honeypot validator with unsupported content type."""
        # Line 118: return None when content-type doesn't match form or json
        mock_func = Mock()
        mock_func.__name__ = mock_func.__qualname__ = "test_func"
        mock_func.__module__ = "test_module"

        honeypot_decorator = decorator.honeypot_detection(["trap_field"])
        decorated_func = honeypot_decorator(mock_func)

        route_id = decorated_func._guard_route_id  # type: ignore[attr-defined]
        route_config = decorator.get_route_config(route_id)
        assert route_config is not None
        validator = route_config.custom_validators[0]

        # Test with unsupported content-type
        mock_request = AsyncMock()
        mock_request.method = "POST"
        mock_request.headers.get = (
            lambda key, default="": "text/plain" if key == "content-type" else default
        )

        result = await validator(mock_request)
        assert result is None

        # Test with multipart/form-data (not explicitly supported)
        mock_request.headers.get = (
            lambda key, default="": "multipart/form-data"
            if key == "content-type"
            else default
        )

        result = await validator(mock_request)
        assert result is None

    @pytest.mark.parametrize(
        "method",
        ["GET", "DELETE", "OPTIONS", "HEAD"],
    )
    async def test_honeypot_various_non_modifying_methods(
        self, decorator: SecurityDecorator, method: str
    ) -> None:
        """Test honeypot validator with various non-modifying HTTP methods."""
        mock_func = Mock()
        mock_func.__name__ = mock_func.__qualname__ = "test_func"
        mock_func.__module__ = "test_module"

        honeypot_decorator = decorator.honeypot_detection(["trap_field"])
        decorated_func = honeypot_decorator(mock_func)

        route_id = decorated_func._guard_route_id  # type: ignore[attr-defined]
        route_config = decorator.get_route_config(route_id)
        assert route_config is not None
        validator = route_config.custom_validators[0]

        mock_request = AsyncMock()
        mock_request.method = method

        result = await validator(mock_request)
        assert result is None

    @pytest.mark.parametrize(
        "method",
        ["POST", "PUT", "PATCH"],
    )
    async def test_honeypot_modifying_methods_without_content_type(
        self, decorator: SecurityDecorator, method: str
    ) -> None:
        """Test honeypot with modifying methods but no matching content-type."""
        mock_func = Mock()
        mock_func.__name__ = mock_func.__qualname__ = "test_func"
        mock_func.__module__ = "test_module"

        honeypot_decorator = decorator.honeypot_detection(["trap_field"])
        decorated_func = honeypot_decorator(mock_func)

        route_id = decorated_func._guard_route_id  # type: ignore[attr-defined]
        route_config = decorator.get_route_config(route_id)
        assert route_config is not None
        validator = route_config.custom_validators[0]

        # POST/PUT/PATCH without supported content-type
        mock_request = AsyncMock()
        mock_request.method = method
        mock_request.headers.get = (
            lambda key, default="": "application/xml"
            if key == "content-type"
            else default
        )

        result = await validator(mock_request)
        assert result is None
