# guard/core/checks/implementations/required_headers.py
from fastapi import Request, Response, status

from guard.core.checks.base import SecurityCheck
from guard.utils import log_activity


def _classify_header_violation(header_name: str) -> tuple[str, str]:
    """
    Classify header violation for event reporting.

    Args:
        header_name: Name of the missing header

    Returns:
        Tuple of (decorator_type, violation_type)
    """
    header_lower = header_name.lower()

    if header_lower == "x-api-key":
        return "authentication", "api_key_required"
    if header_lower == "authorization":
        return "authentication", "required_header"
    return "advanced", "required_header"


class RequiredHeadersCheck(SecurityCheck):
    """Check for required headers."""

    @property
    def check_name(self) -> str:
        return "required_headers"

    async def _handle_missing_header(
        self, request: Request, header: str
    ) -> Response | None:
        """Handle a missing required header with logging and event reporting."""
        reason = f"Missing required header: {header}"

        # Log suspicious activity
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=reason,
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        # Classify violation
        decorator_type, violation_type = _classify_header_violation(header)

        # Send decorator violation event
        await self.middleware.event_bus.send_middleware_event(
            event_type="decorator_violation",
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=reason,
            decorator_type=decorator_type,
            violation_type=violation_type,
            missing_header=header,
        )

        # Return error response if not in passive mode
        if not self.config.passive_mode:
            return await self.middleware.create_error_response(
                status_code=status.HTTP_400_BAD_REQUEST,
                default_message=reason,
            )
        return None

    async def check(self, request: Request) -> Response | None:
        """Check for required headers."""
        route_config = getattr(request.state, "route_config", None)

        if not route_config or not route_config.required_headers:
            return None

        # Check each required header
        for header, expected in route_config.required_headers.items():
            if expected == "required" and not request.headers.get(header):
                return await self._handle_missing_header(request, header)

        return None
