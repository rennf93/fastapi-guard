# guard/core/checks/implementations/cloud_provider.py
from fastapi import Request, Response, status

from guard.core.checks.base import SecurityCheck
from guard.handlers.cloud_handler import cloud_handler
from guard.utils import log_activity


class CloudProviderCheck(SecurityCheck):
    """Check cloud provider blocking."""

    @property
    def check_name(self) -> str:
        return "cloud_provider"

    async def check(self, request: Request) -> Response | None:
        """Check cloud provider blocking."""
        client_ip = getattr(request.state, "client_ip", None)
        route_config = getattr(request.state, "route_config", None)
        if not client_ip:
            return None

        if self.middleware.route_resolver.should_bypass_check("clouds", route_config):
            return None

        # Get cloud providers to check
        cloud_providers_to_check = (
            self.middleware.route_resolver.get_cloud_providers_to_check(route_config)
        )
        if not cloud_providers_to_check:
            return None

        # Check if IP is from blocked cloud provider
        if not cloud_handler.is_cloud_ip(client_ip, set(cloud_providers_to_check)):
            return None

        # Log suspicious activity
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Blocked cloud provider IP: {client_ip}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        # Send cloud detection events
        await self.middleware.event_bus.send_cloud_detection_events(
            request,
            client_ip,
            cloud_providers_to_check,
            route_config,
            cloud_handler,
            self.config.passive_mode,
        )

        # Return error response if not in passive mode
        if not self.config.passive_mode:
            return await self.middleware.create_error_response(
                status_code=status.HTTP_403_FORBIDDEN,
                default_message="Cloud provider IP not allowed",
            )

        return None
