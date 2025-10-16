# guard/core/checks/implementations/time_window.py
from datetime import datetime, timezone

from fastapi import Request, Response, status

from guard.core.checks.base import SecurityCheck
from guard.utils import log_activity


class TimeWindowCheck(SecurityCheck):
    """Check time window restrictions."""

    @property
    def check_name(self) -> str:
        return "time_window"

    async def _check_time_window(self, time_restrictions: dict[str, str]) -> bool:
        """Check if current time is within allowed time window."""
        try:
            start_time = time_restrictions["start"]
            end_time = time_restrictions["end"]

            # TODO: For simplicity, we'll use UTC for now
            # Production would need proper timezone handling
            # timezone_str = time_restrictions.get("timezone", "UTC")
            current_time = datetime.now(timezone.utc)
            current_hour_minute = current_time.strftime("%H:%M")

            # Handle overnight time windows (e.g., 22:00 to 06:00)
            if start_time > end_time:
                return (
                    current_hour_minute >= start_time or current_hour_minute <= end_time
                )
            else:
                return start_time <= current_hour_minute <= end_time

        except Exception as e:
            self.logger.error(f"Error checking time window: {str(e)}")
            return True  # Allow access if time check fails

    async def check(self, request: Request) -> Response | None:
        """Check time window restrictions."""
        route_config = getattr(request.state, "route_config", None)
        if not route_config or not route_config.time_restrictions:
            return None

        time_allowed = await self._check_time_window(route_config.time_restrictions)
        if not time_allowed:
            await log_activity(
                request,
                self.logger,
                log_type="suspicious",
                reason="Access outside allowed time window",
                level=self.config.log_suspicious_level,
                passive_mode=self.config.passive_mode,
            )
            # Send decorator violation event to agent
            await self.middleware.event_bus.send_middleware_event(
                event_type="decorator_violation",
                request=request,
                action_taken="request_blocked"
                if not self.config.passive_mode
                else "logged_only",
                reason="Access outside allowed time window",
                decorator_type="advanced",
                violation_type="time_restriction",
            )
            if not self.config.passive_mode:
                return await self.middleware.create_error_response(
                    status_code=status.HTTP_403_FORBIDDEN,
                    default_message="Access not allowed at this time",
                )
        return None
