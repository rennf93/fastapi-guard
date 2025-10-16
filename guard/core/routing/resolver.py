# guard/core/routing/resolver.py
from typing import Any

from fastapi import Request

from guard.core.routing.context import RoutingContext
from guard.decorators.base import BaseSecurityDecorator, RouteConfig


class RouteConfigResolver:
    """
    Resolver for route configuration and decorator matching.

    Handles all routing-related operations including decorator access,
    route matching, bypass checking, and configuration resolution.
    """

    def __init__(self, context: RoutingContext):
        """
        Initialize the RouteConfigResolver.

        Args:
            context: RoutingContext with all required dependencies
        """
        self.context = context

    def get_guard_decorator(self, app: Any) -> BaseSecurityDecorator | None:
        """
        Get the guard decorator instance from app state or middleware.

        Args:
            app: FastAPI application instance

        Returns:
            BaseSecurityDecorator instance or None if not available
        """
        # Try to get decorator from app state first
        if app and hasattr(app, "state") and hasattr(app.state, "guard_decorator"):
            app_guard_decorator = app.state.guard_decorator
            if isinstance(app_guard_decorator, BaseSecurityDecorator):
                return app_guard_decorator

        # Fall back to context-level decorator
        return self.context.guard_decorator if self.context.guard_decorator else None

    def is_matching_route(
        self, route: Any, path: str, method: str
    ) -> tuple[bool, str | None]:
        """
        Check if a route matches the request path and method, and has a guard route ID.

        Args:
            route: Route object to check
            path: Request path to match
            method: HTTP method to match

        Returns:
            Tuple of (is_match, route_id): is_match is True if route matches,
            route_id is the guard route ID if found, None otherwise
        """
        # Check if route has required attributes
        if not hasattr(route, "path") or not hasattr(route, "methods"):
            return False, None

        # Check path and method match
        if route.path != path or method not in route.methods:
            return False, None

        # Check for guard route ID
        if not hasattr(route, "endpoint") or not hasattr(
            route.endpoint, "_guard_route_id"
        ):
            return False, None

        return True, route.endpoint._guard_route_id

    def get_route_config(self, request: Request) -> RouteConfig | None:
        """
        Get route-specific security configuration from decorators.

        Args:
            request: The incoming request

        Returns:
            RouteConfig if found, None otherwise
        """
        app = request.scope.get("app")

        # Get decorator instance
        guard_decorator = self.get_guard_decorator(app)
        if not guard_decorator:
            return None

        # Try to find matching route
        if not app:
            return None

        path = request.url.path
        method = request.method

        for route in app.routes:
            is_match, route_id = self.is_matching_route(route, path, method)
            if is_match and route_id:
                return guard_decorator.get_route_config(route_id)

        return None

    def should_bypass_check(
        self, check_name: str, route_config: RouteConfig | None
    ) -> bool:
        """
        Check if a security check should be bypassed.

        Args:
            check_name: Name of the check to evaluate
            route_config: Route-specific configuration (optional)

        Returns:
            True if check should be bypassed, False otherwise
        """
        if not route_config:
            return False
        return (
            check_name in route_config.bypassed_checks
            or "all" in route_config.bypassed_checks
        )

    def get_cloud_providers_to_check(
        self, route_config: RouteConfig | None
    ) -> list[str] | None:
        """
        Get list of cloud providers to check (route-specific or global).

        Args:
            route_config: Route-specific configuration (optional)

        Returns:
            List of provider names or None
        """
        if route_config and route_config.block_cloud_providers:
            return list(route_config.block_cloud_providers)
        if self.context.config.block_cloud_providers:
            return list(self.context.config.block_cloud_providers)
        return None
