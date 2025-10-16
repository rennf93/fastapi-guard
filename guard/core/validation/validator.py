# guard/core/validation/validator.py
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network

from fastapi import Request

from guard.core.validation.context import ValidationContext


class RequestValidator:
    """Handles request validation operations."""

    def __init__(self, context: ValidationContext) -> None:
        """
        Initialize the RequestValidator.

        Args:
            context: Validation context with config, logger, and event bus
        """
        self.context = context

    def is_request_https(self, request: Request) -> bool:
        """
        Check if request is HTTPS, considering X-Forwarded-Proto from trusted proxies.

        Returns:
            True if request is HTTPS or forwarded as HTTPS from trusted proxy
        """
        # Direct HTTPS check
        is_https = request.url.scheme == "https"

        # Check X-Forwarded-Proto from trusted proxies
        if (
            self.context.config.trust_x_forwarded_proto
            and self.context.config.trusted_proxies
            and request.client
        ):
            if self.is_trusted_proxy(request.client.host):
                forwarded_proto = request.headers.get("X-Forwarded-Proto", "")
                is_https = is_https or forwarded_proto.lower() == "https"

        return is_https

    def is_trusted_proxy(self, connecting_ip: str) -> bool:
        """Check if connecting IP is a trusted proxy."""
        for proxy in self.context.config.trusted_proxies:
            if "/" not in proxy:
                # Single IP comparison
                if connecting_ip == proxy:
                    return True
            else:
                # CIDR range comparison
                if ip_address(connecting_ip) in ip_network(proxy, strict=False):
                    return True
        return False

    async def check_time_window(self, time_restrictions: dict[str, str]) -> bool:
        """Check if current time is within allowed time window."""
        try:
            start_time = time_restrictions["start"]
            end_time = time_restrictions["end"]

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
            self.context.logger.error(f"Error checking time window: {e!s}")
            return True  # Allow access if time check fails

    async def is_path_excluded(self, request: Request) -> bool:
        """Check if the request path is excluded from security checks."""
        if any(
            request.url.path.startswith(path)
            for path in self.context.config.exclude_paths
        ):
            # Send path exclusion event for monitoring
            await self.context.event_bus.send_middleware_event(
                event_type="path_excluded",
                request=request,
                action_taken="security_checks_bypassed",
                reason=f"Path {request.url.path} excluded from security checks",
                excluded_path=request.url.path,
                configured_exclusions=self.context.config.exclude_paths,
            )
            return True
        return False
