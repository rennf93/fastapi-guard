# guard/core/checks/implementations/ip_security.py
from fastapi import Request, Response, status

from guard.core.checks.base import SecurityCheck
from guard.core.checks.helpers import check_route_ip_access
from guard.decorators.base import RouteConfig
from guard.handlers.ipban_handler import ip_ban_manager
from guard.utils import is_ip_allowed, log_activity


class IpSecurityCheck(SecurityCheck):
    """Check IP-based security (banning, allowlist/blocklist)."""

    @property
    def check_name(self) -> str:
        return "ip_security"

    async def _check_banned_ip(
        self, request: Request, client_ip: str, route_config: RouteConfig | None
    ) -> Response | None:
        """Check if IP is banned and handle accordingly."""
        if self.middleware.route_resolver.should_bypass_check("ip_ban", route_config):
            return None

        if not await ip_ban_manager.is_ip_banned(client_ip):
            return None

        # Log banned IP access attempt
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Banned IP attempted access: {client_ip}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        if not self.config.passive_mode:
            return await self.middleware.create_error_response(
                status_code=status.HTTP_403_FORBIDDEN,
                default_message="IP address banned",
            )

        return None

    async def _check_route_ip_restrictions(
        self, request: Request, client_ip: str, route_config: RouteConfig
    ) -> Response | None:
        """Check route-specific IP restrictions."""
        route_allowed = await check_route_ip_access(
            client_ip, route_config, self.middleware
        )

        # None means no route-specific rules, fall back to global
        if route_allowed is None or route_allowed:
            return None

        # IP not allowed by route config
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"IP not allowed by route config: {client_ip}",
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
            reason=f"IP {client_ip} blocked",
            decorator_type="access_control",
            violation_type="ip_restriction",
        )

        if not self.config.passive_mode:
            return await self.middleware.create_error_response(
                status_code=status.HTTP_403_FORBIDDEN,
                default_message="Forbidden",
            )

        return None

    async def _check_global_ip_restrictions(
        self, request: Request, client_ip: str
    ) -> Response | None:
        """Check global IP allowlist/blocklist."""
        if await is_ip_allowed(client_ip, self.config, self.middleware.geo_ip_handler):
            return None

        # Log blocked IP
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"IP not allowed: {client_ip}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        # Send global IP filtering event to agent
        await self.middleware.event_bus.send_middleware_event(
            event_type="ip_blocked",
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=f"IP {client_ip} not in global allowlist/blocklist",
            ip_address=client_ip,
            filter_type="global",
        )

        if not self.config.passive_mode:
            return await self.middleware.create_error_response(
                status_code=status.HTTP_403_FORBIDDEN,
                default_message="Forbidden",
            )

        return None

    async def check(self, request: Request) -> Response | None:
        """Check IP security (banning, allowlist/blocklist)."""
        client_ip = getattr(request.state, "client_ip", None)
        route_config = getattr(request.state, "route_config", None)
        if not client_ip:
            return None

        # Check IP banning first
        ban_response = await self._check_banned_ip(request, client_ip, route_config)
        if ban_response:
            return ban_response

        # Check IP allowlist/blocklist (with route overrides)
        if self.middleware.route_resolver.should_bypass_check("ip", route_config):
            return None

        # Route-specific IP restrictions
        if route_config:
            return await self._check_route_ip_restrictions(
                request, client_ip, route_config
            )

        # Global IP restrictions
        return await self._check_global_ip_restrictions(request, client_ip)
