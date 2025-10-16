# guard/core/checks/implementations/emergency_mode.py
from fastapi import Request, Response, status

from guard.core.checks.base import SecurityCheck
from guard.utils import extract_client_ip, log_activity


class EmergencyModeCheck(SecurityCheck):
    """Check emergency mode restrictions - blocks all except whitelisted IPs."""

    @property
    def check_name(self) -> str:
        return "emergency_mode"

    async def check(self, request: Request) -> Response | None:
        """Check emergency mode - blocks all except whitelisted IPs."""
        if not self.config.emergency_mode:
            return None

        # Get client IP from request state (set by RouteConfigCheck)
        client_ip = getattr(request.state, "client_ip", None)
        if not client_ip:
            client_ip = await extract_client_ip(
                request, self.config, self.middleware.agent_handler
            )

        # Allow only emergency whitelist IPs
        if client_ip not in self.config.emergency_whitelist:
            await log_activity(
                request,
                self.logger,
                log_type="suspicious",
                reason=f"[EMERGENCY MODE] Access denied for IP {client_ip}",
                level=self.config.log_suspicious_level,
                passive_mode=self.config.passive_mode,
            )

            # Send emergency mode blocking event
            await self.middleware.event_bus.send_middleware_event(
                event_type="emergency_mode_block",
                request=request,
                action_taken="request_blocked"
                if not self.config.passive_mode
                else "logged_only",
                reason=f"[EMERGENCY MODE] IP {client_ip} not in whitelist",
                emergency_whitelist_count=len(self.config.emergency_whitelist),
                emergency_active=True,
            )

            if not self.config.passive_mode:
                return await self.middleware.create_error_response(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    default_message="Service temporarily unavailable",
                )
        else:
            # Log allowed emergency access
            await log_activity(
                request,
                self.logger,
                log_type="info",
                reason=(
                    f"[EMERGENCY MODE] Allowed access for whitelisted IP {client_ip}"
                ),
                level="INFO",
            )

        return None
