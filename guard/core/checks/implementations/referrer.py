# guard/core/checks/implementations/referrer.py
from fastapi import Request, Response, status

from guard.core.checks.base import SecurityCheck
from guard.core.checks.helpers import is_referrer_domain_allowed
from guard.decorators.base import RouteConfig
from guard.utils import log_activity


class ReferrerCheck(SecurityCheck):
    """Check referrer requirements."""

    @property
    def check_name(self) -> str:
        return "referrer"

    async def _handle_missing_referrer(
        self, request: Request, route_config: RouteConfig
    ) -> Response | None:
        """Handle missing referrer header violation."""
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason="Missing referrer header",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        await self.middleware.event_bus.send_middleware_event(
            event_type="decorator_violation",
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason="Missing referrer header",
            decorator_type="content_filtering",
            violation_type="require_referrer",
            allowed_domains=route_config.require_referrer,
        )

        if not self.config.passive_mode:
            return await self.middleware.create_error_response(
                status_code=status.HTTP_403_FORBIDDEN,
                default_message="Referrer required",
            )

        return None

    async def _handle_invalid_referrer(
        self, request: Request, referrer: str, route_config: RouteConfig
    ) -> Response | None:
        """Handle invalid referrer domain violation."""
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Invalid referrer: {referrer}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        await self.middleware.event_bus.send_middleware_event(
            event_type="decorator_violation",
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=f"Referrer '{referrer}' not in allowed domains",
            decorator_type="content_filtering",
            violation_type="require_referrer",
            referrer=referrer,
            allowed_domains=route_config.require_referrer,
        )

        if not self.config.passive_mode:
            return await self.middleware.create_error_response(
                status_code=status.HTTP_403_FORBIDDEN,
                default_message="Invalid referrer",
            )

        return None

    async def check(self, request: Request) -> Response | None:
        """Check referrer requirements."""
        route_config = getattr(request.state, "route_config", None)
        if not route_config or not route_config.require_referrer:
            return None

        referrer = request.headers.get("referer", "")

        # Handle missing referrer
        if not referrer:
            return await self._handle_missing_referrer(request, route_config)

        # Check if referrer domain is allowed using helper function
        if not is_referrer_domain_allowed(referrer, route_config.require_referrer):
            return await self._handle_invalid_referrer(request, referrer, route_config)

        return None
