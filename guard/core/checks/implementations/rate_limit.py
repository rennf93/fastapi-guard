# guard/core/checks/implementations/rate_limit.py
"""Rate limiting security check with three-tier priority system."""

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

    async def _apply_rate_limit_check(
        self,
        request: Request,
        client_ip: str,
        rate_limit: int,
        window: int,
        event_type: str,
        event_kwargs: dict[str, Any],
    ) -> Response | None:
        """
        Apply rate limit check with given configuration and send events if exceeded.

        This uses the ORIGINAL working delegation pattern from middleware.py:
        Creates a temporary RateLimitManager and calls its check_rate_limit() method.

        Args:
            request: The request object
            client_ip: Client IP address
            rate_limit: Number of requests allowed
            window: Time window in seconds
            event_type: Type of event to send
                (dynamic_rule_violation or decorator_violation)
            event_kwargs: Additional event metadata for agent reporting

        Returns:
            Response if rate limit exceeded (and not in passive mode), None otherwise
        """
        # Create temporary rate limit config and handler
        # This is the ORIGINAL working approach from middleware.py
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

        # Check rate limit using the handler's check_rate_limit() method
        response = await rate_handler.check_rate_limit(
            request, client_ip, self.middleware.create_error_response
        )

        # Send event if rate limit exceeded
        if response is not None:
            await self.middleware.event_bus.send_middleware_event(
                event_type=event_type,
                request=request,
                action_taken="request_blocked"
                if not self.config.passive_mode
                else "logged_only",
                **event_kwargs,
            )

            if self.config.passive_mode:
                return None  # Don't block in passive mode

        return response

    async def check(self, request: Request) -> Response | None:
        """
        Check rate limiting with route overrides and dynamic endpoint-specific config.

        Three-tier priority system:
        1. Endpoint-specific rate limits (from config.endpoint_rate_limits)
        2. Route-specific rate limits (from decorator configuration)
        3. Global rate limiting (from middleware rate_limit_handler)

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

        # Priority 1: Endpoint-specific rate limit (dynamic rules)
        if endpoint_path in self.config.endpoint_rate_limits:
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

        # Priority 2: Route-specific rate limit (decorator config)
        if route_config and route_config.rate_limit is not None:
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

        # Priority 3: Global rate limiting
        # The rate_limit_handler will check if enable_rate_limiting is True
        response = await self.middleware.rate_limit_handler.check_rate_limit(
            request, client_ip, self.middleware.create_error_response
        )

        if response is not None and self.config.passive_mode:
            return None  # Don't block in passive mode

        return response
