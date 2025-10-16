# guard/core/checks/implementations/user_agent.py
from fastapi import Request, Response, status

from guard.core.checks.base import SecurityCheck
from guard.core.checks.helpers import check_user_agent_allowed
from guard.utils import log_activity


class UserAgentCheck(SecurityCheck):
    """Check user agent restrictions."""

    @property
    def check_name(self) -> str:
        return "user_agent"

    async def check(self, request: Request) -> Response | None:
        """Check user agent restrictions."""
        route_config = getattr(request.state, "route_config", None)
        user_agent = request.headers.get("User-Agent", "")

        if not await check_user_agent_allowed(user_agent, route_config, self.config):
            await log_activity(
                request,
                self.logger,
                log_type="suspicious",
                reason=f"Blocked user agent: {user_agent}",
                level=self.config.log_suspicious_level,
                passive_mode=self.config.passive_mode,
            )

            # Send decorator violation event only for route-specific blocks
            if route_config and route_config.blocked_user_agents:
                # Route-specific user agent block
                await self.middleware.event_bus.send_middleware_event(
                    event_type="decorator_violation",
                    request=request,
                    action_taken="request_blocked"
                    if not self.config.passive_mode
                    else "logged_only",
                    reason=f"User agent '{user_agent}' blocked",
                    decorator_type="access_control",
                    violation_type="user_agent",
                    blocked_user_agent=user_agent,
                )
            else:
                # Global user agent block
                await self.middleware.event_bus.send_middleware_event(
                    event_type="user_agent_blocked",
                    request=request,
                    action_taken="request_blocked"
                    if not self.config.passive_mode
                    else "logged_only",
                    reason=f"User agent '{user_agent}' in global blocklist",
                    user_agent=user_agent,
                    filter_type="global",
                )

            if not self.config.passive_mode:
                return await self.middleware.create_error_response(
                    status_code=status.HTTP_403_FORBIDDEN,
                    default_message="User-Agent not allowed",
                )
        return None
