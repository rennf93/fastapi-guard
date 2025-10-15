# guard/middleware_components/checks/implementations/required_headers.py
"""Required headers security check."""

from fastapi import Request, Response, status

from guard.middleware_components.checks.base import SecurityCheck
from guard.utils import log_activity


class RequiredHeadersCheck(SecurityCheck):
    """Check for required headers."""

    @property
    def check_name(self) -> str:
        return "required_headers"

    async def check(self, request: Request) -> Response | None:
        """Check for required headers."""
        route_config = getattr(request.state, "route_config", None)

        if not route_config or not route_config.required_headers:
            return None

        for header, expected in route_config.required_headers.items():
            if expected == "required" and not request.headers.get(header):
                # Log suspicious activity for missing required header
                await log_activity(
                    request,
                    self.logger,
                    log_type="suspicious",
                    reason=f"Missing required header: {header}",
                    level=self.config.log_suspicious_level,
                    passive_mode=self.config.passive_mode,
                )

                # Determine decorator type based on header name
                decorator_type = (
                    "authentication"
                    if header.lower() in ["x-api-key", "authorization"]
                    else "advanced"
                )
                violation_type = (
                    "api_key_required"
                    if header.lower() == "x-api-key"
                    else "required_header"
                )

                # Send decorator violation event to agent
                await self.middleware.event_bus.send_middleware_event(
                    event_type="decorator_violation",
                    request=request,
                    action_taken="request_blocked"
                    if not self.config.passive_mode
                    else "logged_only",
                    reason=f"Missing required header: {header}",
                    decorator_type=decorator_type,
                    violation_type=violation_type,
                    missing_header=header,
                )
                if not self.config.passive_mode:
                    return await self.middleware.create_error_response(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        default_message=f"Missing required header: {header}",
                    )
        return None
