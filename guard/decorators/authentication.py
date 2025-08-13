# guard/decorators/authentication.py
from collections.abc import Callable
from typing import Any

from guard.decorators.base import BaseSecurityMixin


class AuthenticationMixin(BaseSecurityMixin):
    """Mixin for authentication decorators."""

    def require_https(self) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Force HTTPS for this specific route."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            route_config.require_https = True
            return self._apply_route_config(func)

        return decorator

    def require_auth(
        self, type: str = "bearer"
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Require authentication for this route."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            route_config.auth_required = type
            return self._apply_route_config(func)

        return decorator

    def api_key_auth(
        self, header_name: str = "X-API-Key"
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """
        Require API key authentication for this endpoint.

        Args:
            header_name: Name of the header containing the API key

        Example:
            @guard_decorator.api_key_auth("X-API-Key")
            def protected_endpoint():
                return {"data": "api key required"}
        """

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            route_config.api_key_required = True
            route_config.required_headers[header_name] = "required"
            return self._apply_route_config(func)

        return decorator

    def require_headers(
        self, headers: dict[str, str]
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Require specific headers to be present."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            route_config.required_headers.update(headers)
            return self._apply_route_config(func)

        return decorator
