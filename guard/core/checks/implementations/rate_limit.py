# guard/core/checks/implementations/rate_limit.py
from typing import Any

from fastapi import Request, Response

from guard.core.checks.base import SecurityCheck


class RateLimitCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "rate_limit"

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
        endpoint_path: str = "",
    ) -> Response | None:
        response = await self.middleware.rate_limit_handler.check_rate_limit(
            request,
            client_ip,
            self.middleware.create_error_response,
            endpoint_path=endpoint_path,
            rate_limit=rate_limit,
            rate_limit_window=window,
        )

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
            endpoint_path=endpoint_path,
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
            endpoint_path=request.url.path,
        )

    async def _check_geo_rate_limit(
        self, request: Request, client_ip: str, route_config: Any
    ) -> Response | None:
        """Check geo-based rate limits using the geo IP handler."""
        if not route_config or not route_config.geo_rate_limits:
            return None

        geo_handler = self.config.geo_ip_handler
        if not geo_handler:
            return None

        country = geo_handler.get_country(client_ip)
        limits = route_config.geo_rate_limits

        if country and country in limits:
            rate_limit, window = limits[country]
        elif "*" in limits:
            rate_limit, window = limits["*"]
        else:
            return None

        return await self._apply_rate_limit_check(
            request,
            client_ip,
            rate_limit,
            window,
            "decorator_violation",
            {
                "reason": (
                    f"Geo rate limit exceeded for {country or 'unknown'}: "
                    f"{rate_limit} requests per {window}s"
                ),
                "decorator_type": "geo_rate_limiting",
                "violation_type": "geo_rate_limit",
                "rate_limit": rate_limit,
                "window": window,
            },
            endpoint_path=request.url.path,
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
        if getattr(request.state, "is_whitelisted", False):
            return None

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

        # Priority 3: Geo-based rate limit
        if response := await self._check_geo_rate_limit(
            request, client_ip, route_config
        ):
            return response

        # Priority 4: Global rate limiting
        return await self._check_global_rate_limit(request, client_ip)
