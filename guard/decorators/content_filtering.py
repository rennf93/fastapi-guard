# guard/decorators/content_filtering.py
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import Request, Response

from guard.decorators.base import BaseSecurityMixin


class ContentFilteringMixin(BaseSecurityMixin):
    """Mixin for content and request filtering decorators."""

    def block_user_agents(
        self, patterns: list[str]
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Block specific user agent patterns for this route."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            route_config.blocked_user_agents.extend(patterns)
            return self._apply_route_config(func)

        return decorator

    def content_type_filter(
        self, allowed_types: list[str]
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """
        Restrict allowed content types for this endpoint.

        Args:
            allowed_types: List of allowed MIME types

        Example:
            @guard_decorator.content_type_filter(["application/json", "text/plain"])
            def api_endpoint():
                return {"message": "json or text only"}
        """

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            route_config.allowed_content_types = allowed_types
            return self._apply_route_config(func)

        return decorator

    def max_request_size(
        self, size_bytes: int
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """
        Limit request body size for this endpoint.

        Args:
            size_bytes: Maximum request size in bytes

        Example:
            @guard_decorator.max_request_size(1024 * 1024)  # 1MB limit
            def upload_endpoint():
                return {"status": "uploaded"}
        """

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            route_config.max_request_size = size_bytes
            return self._apply_route_config(func)

        return decorator

    def require_referrer(
        self, allowed_domains: list[str]
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """
        Require requests to come from specific referrer domains.

        Args:
            allowed_domains: List of allowed referrer domains

        Example:
            @guard_decorator.require_referrer(["example.com", "app.example.com"])
            def api_endpoint():
                return {"message": "referrer validated"}
        """

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            route_config.require_referrer = allowed_domains
            return self._apply_route_config(func)

        return decorator

    def custom_validation(
        self,
        validator: Callable[[Request], Awaitable[Response | None]],
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Add custom validation logic to this route."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            route_config.custom_validators.append(validator)
            return self._apply_route_config(func)

        return decorator
