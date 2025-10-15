# guard/checks/implementations.py
import time

from fastapi import Request, Response

from guard.checks.base import SecurityCheck
from guard.utils import extract_client_ip, log_activity


class HttpsEnforcementCheck(SecurityCheck):
    """Check and enforce HTTPS requirements."""

    @property
    def check_name(self) -> str:
        return "https_enforcement"

    async def check(self, request: Request) -> Response | None:
        """Check HTTPS enforcement."""
        route_config = self.middleware._get_route_decorator_config(request)
        return await self.middleware._check_https_enforcement(request, route_config)


class NoClientCheck(SecurityCheck):
    """Handle requests with no client information."""

    @property
    def check_name(self) -> str:
        return "no_client"

    async def check(self, request: Request) -> Response | None:
        """Handle no client - this needs call_next, will be handled differently."""
        # Note: This check is special as it needs call_next
        # Will be handled in dispatch directly
        return None


class EmergencyModeCheck(SecurityCheck):
    """Check emergency mode restrictions."""

    @property
    def check_name(self) -> str:
        return "emergency_mode"

    async def check(self, request: Request) -> Response | None:
        """Check emergency mode."""
        # Need client_ip which is extracted separately
        # This will be handled with context passed to checks
        return None


class RouteConfigCheck(SecurityCheck):
    """
    Extracts and attaches route configuration to request state.

    This is not a blocking check, but prepares context for other checks.
    """

    @property
    def check_name(self) -> str:
        return "route_config"

    async def check(self, request: Request) -> Response | None:
        """Extract route config and attach to request state."""
        route_config = self.middleware._get_route_decorator_config(request)
        # Store in request state for other checks to access
        request.state.route_config = route_config
        request.state.client_ip = await extract_client_ip(
            request, self.config, self.middleware.agent_handler
        )
        return None


class ExcludedPathCheck(SecurityCheck):
    """Check if path is excluded from security checks."""

    @property
    def check_name(self) -> str:
        return "excluded_path"

    async def check(self, request: Request) -> Response | None:
        """Check excluded paths - special handling needed."""
        # This needs call_next, will be handled in dispatch
        return None


class BypassSecurityCheck(SecurityCheck):
    """Check if security checks should be bypassed."""

    @property
    def check_name(self) -> str:
        return "bypass_security"

    async def check(self, request: Request) -> Response | None:
        """Check bypass - special handling needed."""
        # This needs call_next, will be handled in dispatch
        return None


class RequestLoggingCheck(SecurityCheck):
    """Log incoming requests."""

    @property
    def check_name(self) -> str:
        return "request_logging"

    async def check(self, request: Request) -> Response | None:
        """Log the request."""
        await log_activity(request, self.logger, level=self.config.log_request_level)
        return None


class RequestSizeContentCheck(SecurityCheck):
    """Check request size and content type restrictions."""

    @property
    def check_name(self) -> str:
        return "request_size_content"

    async def check(self, request: Request) -> Response | None:
        """Check request size and content type."""
        route_config = getattr(request.state, "route_config", None)
        return await self.middleware._check_request_size_and_content(
            request, route_config
        )


class RequiredHeadersCheck(SecurityCheck):
    """Check for required headers."""

    @property
    def check_name(self) -> str:
        return "required_headers"

    async def check(self, request: Request) -> Response | None:
        """Check required headers."""
        route_config = getattr(request.state, "route_config", None)
        return await self.middleware._check_required_headers(request, route_config)


class AuthenticationCheck(SecurityCheck):
    """Check authentication requirements."""

    @property
    def check_name(self) -> str:
        return "authentication"

    async def check(self, request: Request) -> Response | None:
        """Check authentication."""
        route_config = getattr(request.state, "route_config", None)
        return await self.middleware._check_authentication(request, route_config)


class ReferrerCheck(SecurityCheck):
    """Check referrer requirements."""

    @property
    def check_name(self) -> str:
        return "referrer"

    async def check(self, request: Request) -> Response | None:
        """Check referrer."""
        route_config = getattr(request.state, "route_config", None)
        return await self.middleware._check_referrer(request, route_config)


class CustomValidatorsCheck(SecurityCheck):
    """Check custom validators."""

    @property
    def check_name(self) -> str:
        return "custom_validators"

    async def check(self, request: Request) -> Response | None:
        """Check custom validators."""
        route_config = getattr(request.state, "route_config", None)
        return await self.middleware._check_custom_validators(request, route_config)


class TimeWindowCheck(SecurityCheck):
    """Check time window restrictions."""

    @property
    def check_name(self) -> str:
        return "time_window"

    async def check(self, request: Request) -> Response | None:
        """Check time window restrictions."""
        route_config = getattr(request.state, "route_config", None)
        return await self.middleware._check_time_window_restrictions(
            request, route_config
        )


class CloudIpRefreshCheck(SecurityCheck):
    """Refresh cloud IP ranges periodically."""

    @property
    def check_name(self) -> str:
        return "cloud_ip_refresh"

    async def check(self, request: Request) -> Response | None:
        """Refresh cloud IP ranges if needed."""
        if (
            self.config.block_cloud_providers
            and time.time() - self.middleware.last_cloud_ip_refresh > 3600
        ):
            await self.middleware.refresh_cloud_ip_ranges()
        return None


class IpSecurityCheck(SecurityCheck):
    """Check IP-based security (banning, allowlist/blocklist)."""

    @property
    def check_name(self) -> str:
        return "ip_security"

    async def check(self, request: Request) -> Response | None:
        """Check IP security."""
        client_ip = getattr(request.state, "client_ip", None)
        route_config = getattr(request.state, "route_config", None)
        if not client_ip:
            return None
        return await self.middleware._check_ip_security(
            request, client_ip, route_config
        )


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
        return await self.middleware._check_cloud_providers(
            request, client_ip, route_config
        )


class UserAgentCheck(SecurityCheck):
    """Check user agent restrictions."""

    @property
    def check_name(self) -> str:
        return "user_agent"

    async def check(self, request: Request) -> Response | None:
        """Check user agent."""
        route_config = getattr(request.state, "route_config", None)
        return await self.middleware._check_user_agent(request, route_config)


class RateLimitCheck(SecurityCheck):
    """Check rate limiting."""

    @property
    def check_name(self) -> str:
        return "rate_limit"

    async def check(self, request: Request) -> Response | None:
        """Check rate limiting."""
        client_ip = getattr(request.state, "client_ip", None)
        route_config = getattr(request.state, "route_config", None)

        if not client_ip:
            return None

        # Check if rate limit should be bypassed
        if route_config and self.middleware._should_bypass_check(
            "rate_limit", route_config
        ):
            return None

        return await self.middleware._check_rate_limit(request, client_ip, route_config)


class SuspiciousActivityCheck(SecurityCheck):
    """Check for suspicious/penetration attempt patterns."""

    @property
    def check_name(self) -> str:
        return "suspicious_activity"

    async def check(self, request: Request) -> Response | None:
        """Check for suspicious activity."""
        client_ip = getattr(request.state, "client_ip", None)
        route_config = getattr(request.state, "route_config", None)
        if not client_ip:
            return None
        return await self.middleware._check_suspicious_activity(
            request, client_ip, route_config
        )


class CustomRequestCheck(SecurityCheck):
    """Check custom request validation."""

    @property
    def check_name(self) -> str:
        return "custom_request"

    async def check(self, request: Request) -> Response | None:
        """Check custom request validation."""
        return await self.middleware._check_custom_request(request)
