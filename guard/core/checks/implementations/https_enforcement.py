# guard/core/checks/implementations/https_enforcement.py
from fastapi import Request, Response

from guard.core.checks.base import SecurityCheck


class HttpsEnforcementCheck(SecurityCheck):
    """Check and enforce HTTPS requirements."""

    @property
    def check_name(self) -> str:
        return "https_enforcement"

    def _is_request_https(self, request: Request) -> bool:
        """
        Check if request is HTTPS, considering X-Forwarded-Proto from trusted proxies.

        Returns:
            True if request is HTTPS or forwarded as HTTPS from trusted proxy
        """
        # Direct HTTPS check
        is_https = request.url.scheme == "https"

        # Check X-Forwarded-Proto from trusted proxies
        if (
            self.config.trust_x_forwarded_proto
            and self.config.trusted_proxies
            and request.client
        ):
            if self._is_trusted_proxy(request.client.host):
                forwarded_proto = request.headers.get("X-Forwarded-Proto", "")
                is_https = is_https or forwarded_proto.lower() == "https"

        return is_https

    def _is_trusted_proxy(self, connecting_ip: str) -> bool:
        """Check if connecting IP is a trusted proxy."""
        from ipaddress import ip_address, ip_network

        for proxy in self.config.trusted_proxies:
            if "/" not in proxy:
                # Single IP comparison
                if connecting_ip == proxy:
                    return True
            else:
                # CIDR range comparison
                if ip_address(connecting_ip) in ip_network(proxy, strict=False):
                    return True
        return False

    async def _create_https_redirect(self, request: Request) -> Response:
        """
        Create HTTPS redirect response with custom modifier if configured.

        Delegates to ErrorResponseFactory for redirect creation.
        """
        return await self.middleware.response_factory.create_https_redirect(request)

    async def check(self, request: Request) -> Response | None:
        """Check HTTPS enforcement."""
        route_config = getattr(request.state, "route_config", None)

        # Check if HTTPS is required
        https_required = (
            route_config.require_https if route_config else self.config.enforce_https
        )
        if not https_required:
            return None

        # Check if request is HTTPS
        if self._is_request_https(request):
            return None

        # HTTPS required but not present - send event and redirect
        await self.middleware.event_bus.send_https_violation_event(
            request, route_config
        )

        if not self.config.passive_mode:
            return await self._create_https_redirect(request)

        return None
