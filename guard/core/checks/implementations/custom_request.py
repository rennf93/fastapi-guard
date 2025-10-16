# guard/core/checks/implementations/custom_request.py
from fastapi import Request, Response

from guard.core.checks.base import SecurityCheck


class CustomRequestCheck(SecurityCheck):
    """Check custom request validation."""

    @property
    def check_name(self) -> str:
        return "custom_request"

    async def check(self, request: Request) -> Response | None:
        """Check custom request validation."""
        if not self.config.custom_request_check:
            return None

        custom_response = await self.config.custom_request_check(request)
        if custom_response:
            # Send custom request check event
            await self.middleware.event_bus.send_middleware_event(
                event_type="custom_request_check",
                request=request,
                action_taken="request_blocked"
                if not self.config.passive_mode
                else "logged_only",
                reason="Custom request check returned blocking response",
                response_status=custom_response.status_code
                if hasattr(custom_response, "status_code")
                else "unknown",
                check_function=self.config.custom_request_check.__name__
                if hasattr(self.config.custom_request_check, "__name__")
                else "anonymous",
            )

            if not self.config.passive_mode:
                return await self.middleware.response_factory.apply_modifier(
                    custom_response
                )
        return None
