# guard/core/checks/implementations/custom_validators.py
from fastapi import Request, Response

from guard.core.checks.base import SecurityCheck
from guard.utils import log_activity


class CustomValidatorsCheck(SecurityCheck):
    """Check custom validators."""

    @property
    def check_name(self) -> str:
        return "custom_validators"

    async def check(self, request: Request) -> Response | None:
        """Check custom validators."""
        route_config = getattr(request.state, "route_config", None)
        if not route_config or not route_config.custom_validators:
            return None

        for validator in route_config.custom_validators:
            validation_response = await validator(request)
            if validation_response:
                # Log suspicious activity for custom validation failure
                await log_activity(
                    request,
                    self.logger,
                    log_type="suspicious",
                    reason="Custom validation failed",
                    level=self.config.log_suspicious_level,
                    passive_mode=self.config.passive_mode,
                )

                # Send decorator violation event for custom validation failure
                await self.middleware.event_bus.send_middleware_event(
                    event_type="decorator_violation",
                    request=request,
                    action_taken="request_blocked"
                    if not self.config.passive_mode
                    else "logged_only",
                    reason="Custom validation failed",
                    decorator_type="content_filtering",
                    violation_type="custom_validation",
                    validator_name=getattr(validator, "__name__", "anonymous"),
                )
                if not self.config.passive_mode and isinstance(
                    validation_response, Response
                ):
                    return validation_response
        return None
