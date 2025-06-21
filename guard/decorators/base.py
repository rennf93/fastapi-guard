from collections.abc import Callable
from typing import Any

from fastapi import Request

from guard.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard.models import SecurityConfig


class RouteConfig:
    """Per-route security configuration that can override global settings."""

    def __init__(self) -> None:
        self.rate_limit: int | None = None
        self.rate_limit_window: int | None = None
        self.ip_whitelist: list[str] | None = None
        self.ip_blacklist: list[str] | None = None
        self.blocked_countries: list[str] | None = None
        self.allowed_countries: list[str] | None = None
        self.bypassed_checks: set[str] = set()
        self.require_https: bool = False
        self.auth_required: str | None = None
        self.custom_validators: list[Callable] = []
        self.blocked_user_agents: list[str] = []
        self.required_headers: dict[str, str] = {}
        # Behavioral analysis fields
        self.behavior_rules: list[BehaviorRule] = []
        # Additional security fields
        self.block_cloud_providers: set[str] = set()
        self.max_request_size: int | None = None
        self.allowed_content_types: list[str] | None = None
        self.time_restrictions: dict[str, str] | None = None
        self.enable_suspicious_detection: bool = True
        self.require_referrer: list[str] | None = None
        self.api_key_required: bool = False
        self.session_limits: dict[str, int] | None = None


class BaseSecurityMixin:
    """Base mixin class that provides common methods for all security mixins."""

    def _ensure_route_config(self, func: Callable[..., Any]) -> RouteConfig:
        """Must be implemented by BaseSecurityDecorator."""
        raise NotImplementedError("This mixin must be used with BaseSecurityDecorator")

    def _apply_route_config(self, func: Callable[..., Any]) -> Callable[..., Any]:
        """Must be implemented by BaseSecurityDecorator."""
        raise NotImplementedError("This mixin must be used with BaseSecurityDecorator")


class BaseSecurityDecorator:
    """Base class for all security decorators with common functionality."""

    def __init__(self, config: SecurityConfig) -> None:
        self.config = config
        self._route_configs: dict[str, RouteConfig] = {}
        self.behavior_tracker = BehaviorTracker(config)

    def get_route_config(self, route_id: str) -> RouteConfig | None:
        """Get security config for a specific route."""
        return self._route_configs.get(route_id)

    def _get_route_id(self, func: Callable[..., Any]) -> str:
        """Generate a unique route identifier."""
        return f"{func.__module__}.{func.__qualname__}"

    def _ensure_route_config(self, func: Callable[..., Any]) -> RouteConfig:
        """Ensure a route config exists for the function."""
        route_id = self._get_route_id(func)
        if route_id not in self._route_configs:
            config = RouteConfig()
            config.enable_suspicious_detection = (
                self.config.enable_penetration_detection
            )
            self._route_configs[route_id] = config
        return self._route_configs[route_id]

    def _apply_route_config(self, func: Callable[..., Any]) -> Callable[..., Any]:
        """Apply route configuration to a function."""
        route_id = self._get_route_id(func)
        # TODO: Find a proper way to define the type of the function
        func._guard_route_id = route_id  # type: ignore[attr-defined]
        return func

    async def initialize_behavior_tracking(self, redis_handler: Any = None) -> None:
        """Initialize behavioral tracking with optional Redis backend."""
        if redis_handler:
            await self.behavior_tracker.initialize_redis(redis_handler)


# Extract route config from FastAPI route
def get_route_decorator_config(
    request: Request, decorator_handler: BaseSecurityDecorator
) -> RouteConfig | None:
    """Extract route security configuration from the current request."""
    if hasattr(request, "scope") and "route" in request.scope:
        route = request.scope["route"]
        if hasattr(route, "endpoint") and hasattr(route.endpoint, "_guard_route_id"):
            route_id = route.endpoint._guard_route_id
            return decorator_handler.get_route_config(route_id)
    return None
