# guard/core/bypass/handler.py
from collections.abc import Awaitable, Callable

from fastapi import Request, Response

from guard.core.bypass.context import BypassContext
from guard.decorators.base import RouteConfig


class BypassHandler:
    """Handles security check bypassing operations."""

    def __init__(self, context: BypassContext) -> None:
        """
        Initialize the BypassHandler.

        Args:
            context: Bypass context with config, logger, and dependencies
        """
        self.context = context

    async def handle_passthrough(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response | None:
        """
        Handle special cases that require immediate passthrough.

        This includes requests with no client information and excluded paths.

        Returns:
            Response if passthrough is needed, None otherwise
        """
        # No client information
        if not request.client:
            response = await call_next(request)
            return await self.context.response_factory.apply_modifier(response)

        # Excluded paths
        if await self.context.validator.is_path_excluded(request):
            response = await call_next(request)
            return await self.context.response_factory.apply_modifier(response)

        return None

    async def handle_security_bypass(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
        route_config: RouteConfig | None,
    ) -> Response | None:
        """
        Handle bypassed security checks.

        Returns:
            Response if bypass is needed, None otherwise
        """
        if not route_config or not self.context.route_resolver.should_bypass_check(
            "all", route_config
        ):
            return None

        # Send security bypass event for monitoring
        await self.context.event_bus.send_middleware_event(
            event_type="security_bypass",
            request=request,
            action_taken="all_checks_bypassed",
            reason="Route configured to bypass all security checks",
            bypassed_checks=list(route_config.bypassed_checks),
            endpoint=str(request.url.path),
        )

        if not self.context.config.passive_mode:
            response = await call_next(request)
            return await self.context.response_factory.apply_modifier(response)

        return None
