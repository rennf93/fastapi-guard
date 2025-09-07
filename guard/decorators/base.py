# guard/decorators/base.py
from collections.abc import Callable
from datetime import datetime, timezone
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
        self.whitelist_countries: list[str] | None = None
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
        self.agent_handler: Any = None

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

    async def initialize_agent(self, agent_handler: Any) -> None:
        """Initialize agent integration for decorator-based security."""
        self.agent_handler = agent_handler
        # Initialize behavior tracker with agent
        await self.behavior_tracker.initialize_agent(agent_handler)

    async def send_decorator_event(
        self,
        event_type: str,
        request: Request,
        action_taken: str,
        reason: str,
        decorator_type: str,
        **kwargs: Any,
    ) -> None:
        """Send decorator-specific security events to agent."""
        if not self.agent_handler:
            return

        try:
            # Extract client IP using existing utility
            from guard.utils import extract_client_ip

            client_ip = await extract_client_ip(
                request, self.config, self.agent_handler
            )

            from guard_agent import SecurityEvent

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=event_type,
                ip_address=client_ip,
                country=None,  # Will be enriched by geo handler if available
                user_agent=request.headers.get("User-Agent"),
                action_taken=action_taken,
                reason=reason,
                endpoint=str(request.url.path),
                method=request.method,
                decorator_type=decorator_type,
                metadata=kwargs,
            )

            await self.agent_handler.send_event(event)

        except Exception as e:
            # Don't let agent errors break decorator functionality
            import logging

            logging.getLogger("fastapi_guard.decorators.base").error(
                f"Failed to send decorator event to agent: {e}"
            )

    async def send_access_denied_event(
        self,
        request: Request,
        reason: str,
        decorator_type: str,
        **metadata: Any,
    ) -> None:
        """Helper method for access denied events."""
        await self.send_decorator_event(
            event_type="access_denied",
            request=request,
            action_taken="blocked",
            reason=reason,
            decorator_type=decorator_type,
            **metadata,
        )

    async def send_authentication_failed_event(
        self,
        request: Request,
        reason: str,
        auth_type: str,
        **metadata: Any,
    ) -> None:
        """Helper method for authentication failure events."""
        await self.send_decorator_event(
            event_type="authentication_failed",
            request=request,
            action_taken="blocked",
            reason=reason,
            decorator_type="authentication",
            auth_type=auth_type,
            **metadata,
        )

    async def send_rate_limit_event(
        self,
        request: Request,
        limit: int,
        window: int,
        **metadata: Any,
    ) -> None:
        """Helper method for rate limit events."""
        await self.send_decorator_event(
            event_type="rate_limited",
            request=request,
            action_taken="blocked",
            reason=f"Rate limit exceeded: {limit} requests per {window}s",
            decorator_type="rate_limiting",
            limit=limit,
            window=window,
            **metadata,
        )

    async def send_decorator_violation_event(
        self,
        request: Request,
        violation_type: str,
        reason: str,
        **metadata: Any,
    ) -> None:
        """Helper method for general decorator violations."""
        await self.send_decorator_event(
            event_type="decorator_violation",
            request=request,
            action_taken="blocked",
            reason=reason,
            decorator_type=violation_type,
            **metadata,
        )


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
