# guard/core/checks/implementations/authentication.py
from fastapi import Request, Response, status

from guard.core.checks.base import SecurityCheck
from guard.core.checks.helpers import validate_auth_header
from guard.decorators.base import RouteConfig
from guard.utils import log_activity


class AuthenticationCheck(SecurityCheck):
    """Check authentication requirements."""

    @property
    def check_name(self) -> str:
        return "authentication"

    async def _handle_auth_failure(
        self, request: Request, auth_reason: str, route_config: RouteConfig
    ) -> Response | None:
        """Handle authentication failure with logging and events."""
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Authentication failure: {auth_reason}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        await self.middleware.event_bus.send_middleware_event(
            event_type="decorator_violation",
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=auth_reason,
            decorator_type="authentication",
            violation_type="require_auth",
            auth_type=route_config.auth_required,
        )

        if not self.config.passive_mode:
            return await self.middleware.create_error_response(
                status_code=status.HTTP_401_UNAUTHORIZED,
                default_message="Authentication required",
            )

        return None

    async def check(self, request: Request) -> Response | None:
        """Check authentication requirements."""
        route_config = getattr(request.state, "route_config", None)
        if not route_config or not route_config.auth_required:
            return None

        auth_header = request.headers.get("authorization", "")

        # Validate authentication header using helper function
        is_valid, auth_reason = validate_auth_header(
            auth_header, route_config.auth_required
        )

        # Handle authentication failure
        if not is_valid:
            return await self._handle_auth_failure(request, auth_reason, route_config)

        return None
