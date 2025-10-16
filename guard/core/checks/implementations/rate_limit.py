# guard/core/checks/implementations/rate_limit.py
from typing import Any

from fastapi import Request, Response

from guard.core.checks.base import SecurityCheck
from guard.handlers.ratelimit_handler import RateLimitManager
from guard.models import SecurityConfig


class RateLimitCheck(SecurityCheck):
    """
    Check rate limiting with three-tier priority:
    1. Endpoint-specific rate limits (dynamic rules)
    2. Route-specific rate limits (decorator config)
    3. Global rate limiting

    This check integrates with Redis for distributed rate limiting and
    sends events to the agent for monitoring rate limit violations.
    """

    @property
    def check_name(self) -> str:
        return "rate_limit"

    async def _create_rate_handler(
        self, rate_limit: int, window: int
    ) -> RateLimitManager:
        """Create and initialize a temporary rate limit handler."""
        rate_config = SecurityConfig(
            rate_limit=rate_limit,
            rate_limit_window=window,
            enable_redis=self.config.enable_redis,
            redis_url=self.config.redis_url,
            redis_prefix=self.config.redis_prefix,
        )
        rate_handler = RateLimitManager(rate_config)
        if self.middleware.redis_handler:
            await rate_handler.initialize_redis(self.middleware.redis_handler)
        return rate_handler

    async def _send_rate_limit_event(
        self,
        request: Request,
        event_type: str,
        event_kwargs: dict[str, Any],
    ) -> None:
        """Send rate limit violation event to agent."""
        await self.middleware.event_bus.send_middleware_event(
            event_type=event_type,
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            **event_kwargs,
        )

    async def _apply_rate_limit_check(
        self,
        request: Request,
        client_ip: str,
        rate_limit: int,
        window: int,
        event_type: str,
        event_kwargs: dict[str, Any],
    ) -> Response | None:
        """Apply rate limit check and send events if exceeded."""
        # Create and use temporary rate limit handler
        rate_handler = await self._create_rate_handler(rate_limit, window)
        response = await rate_handler.check_rate_limit(
            request, client_ip, self.middleware.create_error_response
        )

        # Send event and handle passive mode
        if response is not None:
            await self._send_rate_limit_event(request, event_type, event_kwargs)
            if self.config.passive_mode:
                return None

        return response

    async def _check_endpoint_rate_limit(
        self, request: Request, client_ip: str, endpoint_path: str
    ) -> Response | None:
        """Priority 1: Check endpoint-specific rate limit."""
        if endpoint_path not in self.config.endpoint_rate_limits:
            return None

        rate_limit, window = self.config.endpoint_rate_limits[endpoint_path]
        return await self._apply_rate_limit_check(
            request,
            client_ip,
            rate_limit,
            window,
            "dynamic_rule_violation",
            {
                "reason": (
                    f"Endpoint-specific rate limit exceeded: {rate_limit} "
                    f"requests per {window}s for {endpoint_path}"
                ),
                "rule_type": "endpoint_rate_limit",
                "endpoint": endpoint_path,
                "rate_limit": rate_limit,
                "window": window,
            },
        )

    async def _check_route_rate_limit(
        self, request: Request, client_ip: str, route_config: Any
    ) -> Response | None:
        """Priority 2: Check route-specific rate limit."""
        if not route_config or route_config.rate_limit is None:
            return None

        window = route_config.rate_limit_window or 60
        return await self._apply_rate_limit_check(
            request,
            client_ip,
            route_config.rate_limit,
            window,
            "decorator_violation",
            {
                "reason": (
                    f"Route-specific rate limit exceeded: "
                    f"{route_config.rate_limit} requests per {window}s"
                ),
                "decorator_type": "rate_limiting",
                "violation_type": "rate_limit",
                "rate_limit": route_config.rate_limit,
                "window": window,
            },
        )

    async def _check_global_rate_limit(
        self, request: Request, client_ip: str
    ) -> Response | None:
        """Priority 3: Check global rate limiting."""
        response = await self.middleware.rate_limit_handler.check_rate_limit(
            request, client_ip, self.middleware.create_error_response
        )

        if response is not None and self.config.passive_mode:
            return None

        return response

    async def check(self, request: Request) -> Response | None:
        """
        Check rate limiting with three-tier priority system.

        Returns:
            Response if rate limit exceeded, None if allowed
        """
        client_ip = getattr(request.state, "client_ip", None)
        route_config = getattr(request.state, "route_config", None)

        if not client_ip:
            return None

        # Check if rate limit should be bypassed
        if route_config and self.middleware.route_resolver.should_bypass_check(
            "rate_limit", route_config
        ):
            return None

        endpoint_path = request.url.path

        # Priority 1: Endpoint-specific rate limit
        if response := await self._check_endpoint_rate_limit(
            request, client_ip, endpoint_path
        ):
            return response

        # Priority 2: Route-specific rate limit
        if response := await self._check_route_rate_limit(
            request, client_ip, route_config
        ):
            return response

        # Priority 3: Global rate limiting
        return await self._check_global_rate_limit(request, client_ip)
