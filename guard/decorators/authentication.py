from collections.abc import Callable


class AuthenticationMixin:
    """Mixin for authentication decorators."""

    def require_https(self):
        """Force HTTPS for this specific route."""

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)
            route_config.require_https = True
            return self._apply_route_config(func)

        return decorator

    def require_auth(self, type: str = "bearer"):
        """Require authentication for this route."""

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)
            route_config.auth_required = type
            return self._apply_route_config(func)

        return decorator

    def api_key_auth(self, header_name: str = "X-API-Key"):
        """
        Require API key authentication for this endpoint.

        Args:
            header_name: Name of the header containing the API key

        Example:
            @guard_decorator.api_key_auth("X-API-Key")
            def protected_endpoint():
                return {"data": "api key required"}
        """

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)
            route_config.api_key_required = True
            route_config.required_headers[header_name] = "required"
            return self._apply_route_config(func)

        return decorator

    def require_headers(self, headers: dict[str, str]):
        """Require specific headers to be present."""

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)
            route_config.required_headers.update(headers)
            return self._apply_route_config(func)

        return decorator
