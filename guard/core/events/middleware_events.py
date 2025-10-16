# guard/core/events/middleware_events.py
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import Request

from guard.decorators.base import RouteConfig
from guard.models import SecurityConfig
from guard.utils import extract_client_ip


class SecurityEventBus:
    """Centralized event publishing for middleware security events."""

    def __init__(
        self,
        agent_handler: Any,
        config: SecurityConfig,
        geo_ip_handler: Any = None,
    ):
        """
        Initialize the SecurityEventBus.

        Args:
            agent_handler: The agent handler instance for sending events
            config: Security configuration
            geo_ip_handler: Optional GeoIP handler for country lookup
        """
        self.agent_handler = agent_handler
        self.config = config
        self.geo_ip_handler = geo_ip_handler
        self.logger = logging.getLogger(__name__)

    async def send_middleware_event(
        self,
        event_type: str,
        request: Request,
        action_taken: str,
        reason: str,
        **kwargs: Any,
    ) -> None:
        """
        Send middleware-specific events to agent if enabled.

        This method should only be used for middleware-specific events like
        decorator violations. Domain-specific events (IP bans, rate limits, etc.)
        should be sent by their respective handlers.

        Args:
            event_type: Type of security event
            request: The incoming request
            action_taken: Action that was taken
            reason: Reason for the action
            **kwargs: Additional metadata for the event
        """
        if not self.agent_handler or not self.config.agent_enable_events:
            return

        try:
            client_ip = await extract_client_ip(
                request, self.config, self.agent_handler
            )

            # Get country information if available
            country = None
            if self.geo_ip_handler:
                try:
                    country = self.geo_ip_handler.get_country(client_ip)
                except Exception:
                    # Don't let geo IP lookup failures break event sending
                    pass

            from guard_agent import SecurityEvent

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=event_type,
                ip_address=client_ip,
                country=country,
                user_agent=request.headers.get("User-Agent"),
                action_taken=action_taken,
                reason=reason,
                endpoint=str(request.url.path),
                method=request.method,
                metadata=kwargs,
            )

            await self.agent_handler.send_event(event)
        except Exception as e:
            # Don't let agent errors break the middleware
            self.logger.error(f"Failed to send security event to agent: {e}")

    async def send_https_violation_event(
        self, request: Request, route_config: RouteConfig | None
    ) -> None:
        """
        Send appropriate HTTPS violation event based on route config.

        Args:
            request: The incoming request
            route_config: Route-specific configuration (if any)
        """
        https_url = str(request.url.replace(scheme="https"))

        if route_config and route_config.require_https:
            # Route-specific HTTPS requirement
            await self.send_middleware_event(
                event_type="decorator_violation",
                request=request,
                action_taken="https_redirect",
                reason="Route requires HTTPS but request was HTTP",
                decorator_type="authentication",
                violation_type="require_https",
                original_scheme=request.url.scheme,
                redirect_url=https_url,
            )
        else:
            # Global HTTPS enforcement
            await self.send_middleware_event(
                event_type="https_enforced",
                request=request,
                action_taken="https_redirect",
                reason="HTTP request redirected to HTTPS for security",
                original_scheme=request.url.scheme,
                redirect_url=https_url,
            )

    async def send_cloud_detection_events(
        self,
        request: Request,
        client_ip: str,
        cloud_providers_to_check: list[str],
        route_config: RouteConfig | None,
        cloud_handler: Any,
        passive_mode: bool,
    ) -> None:
        """
        Send cloud provider detection events to handler and middleware.

        Args:
            request: The incoming request
            client_ip: Client IP address
            cloud_providers_to_check: List of cloud providers to check
            route_config: Route-specific configuration (if any)
            cloud_handler: Cloud handler instance
            passive_mode: Whether middleware is in passive mode
        """
        # Send event to cloud handler if details available
        cloud_details = cloud_handler.get_cloud_provider_details(
            client_ip, set(cloud_providers_to_check)
        )
        if cloud_details and cloud_handler.agent_handler:
            provider, network = cloud_details
            await cloud_handler.send_cloud_detection_event(
                client_ip,
                provider,
                network,
                "request_blocked" if not passive_mode else "logged_only",
            )

        # Send decorator violation event for route-specific blocks
        if route_config and route_config.block_cloud_providers:
            await self.send_middleware_event(
                event_type="decorator_violation",
                request=request,
                action_taken="request_blocked" if not passive_mode else "logged_only",
                reason=f"Cloud provider IP {client_ip} blocked",
                decorator_type="access_control",
                violation_type="cloud_provider",
                blocked_providers=list(cloud_providers_to_check),
            )
