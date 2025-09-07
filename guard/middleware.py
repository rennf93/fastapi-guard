# fastapi_guard/middleware.py
import logging
import re
import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import Any

from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from guard.decorators.base import BaseSecurityDecorator, RouteConfig
from guard.handlers.cloud_handler import cloud_handler
from guard.handlers.ipban_handler import ip_ban_manager
from guard.handlers.ratelimit_handler import RateLimitManager
from guard.handlers.security_headers_handler import security_headers_manager
from guard.handlers.suspatterns_handler import sus_patterns_handler
from guard.models import SecurityConfig
from guard.utils import (
    detect_penetration_attempt,
    extract_client_ip,
    is_ip_allowed,
    is_user_agent_allowed,
    log_activity,
    setup_custom_logging,
)


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Middleware for implementing various
    security measures in a FastAPI application.

    This middleware handles rate limiting,
    IP filtering, user agent filtering,
    and detection of potential
    penetration attempts.
    """

    def __init__(self, app: ASGIApp, *, config: SecurityConfig) -> None:
        """
        Initialize the SecurityMiddleware.

        Args:
            app (FastAPI):
                The FastAPI application.
            config (SecurityConfig):
                Configuration object for security settings.
        """
        super().__init__(app)
        self.app = app
        self.config = config
        self.logger = setup_custom_logging(config.custom_log_file)
        self.last_cloud_ip_refresh = 0
        self.suspicious_request_counts: dict[str, int] = {}
        self.last_cleanup = time.time()
        self.rate_limit_handler = RateLimitManager(config)
        self.guard_decorator: BaseSecurityDecorator | None = None

        self._configure_security_headers(config)

        self.geo_ip_handler = None
        if config.whitelist_countries or config.blocked_countries:
            self.geo_ip_handler = config.geo_ip_handler

        # Initialize Redis handler if enabled
        self.redis_handler = None
        if config.enable_redis:
            from guard.handlers.redis_handler import RedisManager

            self.redis_handler = RedisManager(config)

        # Initialize agent handler if enabled
        self.agent_handler = None
        if config.enable_agent:
            agent_config = config.to_agent_config()
            if agent_config:
                try:
                    from guard_agent import guard_agent

                    self.agent_handler = guard_agent(agent_config)
                    self.logger.info("Guard Agent initialized successfully")
                except ImportError:
                    self.logger.warning(
                        "Agent enabled but guard_agent package not installed. "
                        "Install with: pip install fastapi-guard-agent"
                    )
                except Exception as e:
                    self.logger.error(f"Failed to initialize Guard Agent: {e}")
                    self.logger.warning("Continuing without agent functionality")
            else:
                self.logger.warning(
                    "Agent enabled but configuration is invalid. "
                    "Check agent_api_key and other required fields."
                )

    def _configure_security_headers(self, config: SecurityConfig) -> None:
        """Configure security headers manager if enabled."""
        if not config.security_headers:
            security_headers_manager.enabled = False
            return

        if not config.security_headers.get("enabled", True):
            security_headers_manager.enabled = False
            return

        security_headers_manager.enabled = True
        headers_config = config.security_headers
        hsts_config = headers_config.get("hsts", {})

        security_headers_manager.configure(
            enabled=headers_config.get("enabled", True),
            csp=headers_config.get("csp"),
            hsts_max_age=hsts_config.get("max_age"),
            hsts_include_subdomains=hsts_config.get("include_subdomains", True),
            hsts_preload=hsts_config.get("preload", False),
            frame_options=headers_config.get("frame_options", "SAMEORIGIN"),
            content_type_options=headers_config.get("content_type_options", "nosniff"),
            xss_protection=headers_config.get("xss_protection", "1; mode=block"),
            referrer_policy=headers_config.get(
                "referrer_policy", "strict-origin-when-cross-origin"
            ),
            permissions_policy=headers_config.get("permissions_policy", "UNSET"),
            custom_headers=headers_config.get("custom"),
            cors_origins=config.cors_allow_origins if config.enable_cors else None,
            cors_allow_credentials=config.cors_allow_credentials,
            cors_allow_methods=config.cors_allow_methods,
            cors_allow_headers=config.cors_allow_headers,
        )

    def set_decorator_handler(
        self, decorator_handler: BaseSecurityDecorator | None
    ) -> None:
        """Set the SecurityDecorator instance for decorator support."""
        self.guard_decorator = decorator_handler

    async def _send_middleware_event(
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

    async def _send_security_metric(
        self, metric_type: str, value: float, tags: dict[str, str] | None = None
    ) -> None:
        """Send performance metric to agent."""
        if self.agent_handler and self.config.agent_enable_metrics:
            try:
                from guard_agent import SecurityMetric

                metric = SecurityMetric(
                    timestamp=datetime.now(timezone.utc),
                    metric_type=metric_type,
                    value=value,
                    tags=tags or {},
                )
                await self.agent_handler.send_metric(metric)
            except Exception as e:
                # Don't let agent errors break middleware functionality
                logging.getLogger(__name__).error(
                    f"Failed to send metric to agent: {e}"
                )

    async def _collect_request_metrics(
        self, request: Request, response_time: float, status_code: int
    ) -> None:
        """Collect request metrics for agent."""
        if not self.agent_handler or not self.config.agent_enable_metrics:
            return

        endpoint = str(request.url.path)
        method = request.method

        # Response time metric
        await self._send_security_metric(
            "response_time",
            response_time,
            {"endpoint": endpoint, "method": method, "status": str(status_code)},
        )

        # Request count metric
        await self._send_security_metric(
            "request_count", 1.0, {"endpoint": endpoint, "method": method}
        )

        # Error rate metric (for non-2xx responses)
        if status_code >= 400:
            await self._send_security_metric(
                "error_rate",
                1.0,
                {"endpoint": endpoint, "method": method, "status": str(status_code)},
            )

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """
        Dispatch method to handle incoming
        requests and apply security measures.

        This method implements rate limiting,
        IP filtering, user agent filtering,
        and detection of potential
        penetration attempts.

        Args:
            request (Request):
                The incoming request object.
            call_next (Callable[[Request], Awaitable[Response]]):
                The next middleware or route handler in the chain.

        Returns:
            Response: The response object, either
            from the next handler or a security-related response.
        """
        # Get route-specific configuration if decorators are used
        route_config = self._get_route_decorator_config(request)

        # Check HTTPS enforcement
        https_required = (
            route_config.require_https if route_config else self.config.enforce_https
        )
        if https_required:
            is_https = request.url.scheme == "https"

            # Check X-Forwarded-Proto
            if self.config.trust_x_forwarded_proto and self.config.trusted_proxies:
                if request.client:
                    connecting_ip = request.client.host
                    is_trusted_proxy = any(
                        # Check trusted proxy
                        (
                            connecting_ip == proxy
                            if "/" not in proxy
                            else ip_address(connecting_ip)
                            in ip_network(proxy, strict=False)
                        )
                        for proxy in self.config.trusted_proxies
                    )
                    if is_trusted_proxy:
                        # Trust X-Forwarded-Proto header
                        forwarded_proto = request.headers.get("X-Forwarded-Proto", "")
                        is_https = is_https or forwarded_proto.lower() == "https"

            if not is_https:
                # Determine if this is route-specific or global HTTPS enforcement
                if route_config and route_config.require_https:
                    # Send decorator violation event for route-specific HTTPS
                    await self._send_middleware_event(
                        event_type="decorator_violation",
                        request=request,
                        action_taken="https_redirect",
                        reason="Route requires HTTPS but request was HTTP",
                        decorator_type="authentication",
                        violation_type="require_https",
                        original_scheme=request.url.scheme,
                        redirect_url=str(request.url.replace(scheme="https")),
                    )
                else:
                    # Send global HTTPS enforcement event
                    await self._send_middleware_event(
                        event_type="https_enforced",
                        request=request,
                        action_taken="https_redirect",
                        reason="HTTP request redirected to HTTPS for security",
                        original_scheme=request.url.scheme,
                        redirect_url=str(request.url.replace(scheme="https")),
                    )

                if not self.config.passive_mode:
                    https_url = request.url.replace(scheme="https")
                    redirect_response = RedirectResponse(
                        https_url, status_code=status.HTTP_301_MOVED_PERMANENTLY
                    )
                    if self.config.custom_response_modifier:
                        modified_response = await self.config.custom_response_modifier(
                            redirect_response
                        )
                        return modified_response
                    return redirect_response

        if not request.client:
            response = await call_next(request)
            if self.config.custom_response_modifier:
                modified_response = await self.config.custom_response_modifier(response)
                return modified_response
            return response

        # Extract client IP
        client_ip = await extract_client_ip(request, self.config, self.agent_handler)

        # Emergency mode check (agent feature)
        if self.config.emergency_mode:
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
                await self._send_middleware_event(
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
                    return await self.create_error_response(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        default_message="Service temporarily unavailable",
                    )
            else:
                message = "[EMERGENCY MODE] Allowed access for whitelisted IP"
                # Log allowed emergency access
                await log_activity(
                    request,
                    self.logger,
                    log_type="info",
                    reason=f"{message}: {client_ip}",
                    level="INFO",
                )

        # Excluded paths
        if any(request.url.path.startswith(path) for path in self.config.exclude_paths):
            # Send path exclusion event for monitoring
            await self._send_middleware_event(
                event_type="path_excluded",
                request=request,
                action_taken="security_checks_bypassed",
                reason=f"Path {request.url.path} excluded from security checks",
                excluded_path=request.url.path,
                configured_exclusions=self.config.exclude_paths,
            )

            response = await call_next(request)
            if self.config.custom_response_modifier:
                modified_response = await self.config.custom_response_modifier(response)
                return modified_response
            return response

        # Check if security checks should be bypassed
        if route_config and self._should_bypass_check("all", route_config):
            # Send security bypass event for monitoring
            await self._send_middleware_event(
                event_type="security_bypass",
                request=request,
                action_taken="all_checks_bypassed",
                reason="Route configured to bypass all security checks",
                bypassed_checks=list(route_config.bypassed_checks),
                endpoint=str(request.url.path),
            )

            # In passive mode, log but don't actually bypass
            if not self.config.passive_mode:
                response = await call_next(request)
                if self.config.custom_response_modifier:
                    modified_response = await self.config.custom_response_modifier(
                        response
                    )
                    return modified_response
                return response

        # Log request
        await log_activity(request, self.logger, level=self.config.log_request_level)

        # Route-specific request size check
        if route_config and route_config.max_request_size:
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > route_config.max_request_size:
                message = f"Request size {content_length} exceeds limit"

                # Log suspicious activity for oversized request
                await log_activity(
                    request,
                    self.logger,
                    log_type="suspicious",
                    reason=f"{message}: {route_config.max_request_size}",
                    level=self.config.log_suspicious_level,
                    passive_mode=self.config.passive_mode,
                )

                # Send decorator violation event to agent
                await self._send_middleware_event(
                    event_type="decorator_violation",
                    request=request,
                    action_taken="request_blocked"
                    if not self.config.passive_mode
                    else "logged_only",
                    reason=f"{message}: {route_config.max_request_size}",
                    decorator_type="content_filtering",
                    violation_type="max_request_size",
                )
                if not self.config.passive_mode:
                    return await self.create_error_response(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        default_message="Request too large",
                    )

        # Route-specific content type check
        if route_config and route_config.allowed_content_types:
            content_type = request.headers.get("content-type", "").split(";")[0]
            if content_type not in route_config.allowed_content_types:
                # Log suspicious activity for invalid content type
                await log_activity(
                    request,
                    self.logger,
                    log_type="suspicious",
                    reason=f"Invalid content type: {content_type}",
                    level=self.config.log_suspicious_level,
                    passive_mode=self.config.passive_mode,
                )

                message = f"Content type {content_type} not in allowed types"

                # Send decorator violation event to agent
                await self._send_middleware_event(
                    event_type="decorator_violation",
                    request=request,
                    action_taken="request_blocked"
                    if not self.config.passive_mode
                    else "logged_only",
                    reason=f"{message}: {route_config.allowed_content_types}",
                    decorator_type="content_filtering",
                    violation_type="content_type",
                )
                if not self.config.passive_mode:
                    return await self.create_error_response(
                        status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                        default_message="Unsupported content type",
                    )

        # Route-specific header requirements
        if route_config and route_config.required_headers:
            for header, expected in route_config.required_headers.items():
                if expected == "required" and not request.headers.get(header):
                    # Log suspicious activity for missing required header
                    await log_activity(
                        request,
                        self.logger,
                        log_type="suspicious",
                        reason=f"Missing required header: {header}",
                        level=self.config.log_suspicious_level,
                        passive_mode=self.config.passive_mode,
                    )

                    # Determine decorator type based on header name
                    decorator_type = (
                        "authentication"
                        if header.lower() in ["x-api-key", "authorization"]
                        else "advanced"
                    )
                    violation_type = (
                        "api_key_required"
                        if header.lower() == "x-api-key"
                        else "required_header"
                    )

                    # Send decorator violation event to agent
                    await self._send_middleware_event(
                        event_type="decorator_violation",
                        request=request,
                        action_taken="request_blocked"
                        if not self.config.passive_mode
                        else "logged_only",
                        reason=f"Missing required header: {header}",
                        decorator_type=decorator_type,
                        violation_type=violation_type,
                        missing_header=header,
                    )
                    if not self.config.passive_mode:
                        return await self.create_error_response(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            default_message=f"Missing required header: {header}",
                        )

        # Route-specific authentication requirements
        if route_config and route_config.auth_required:
            auth_header = request.headers.get("authorization", "")
            auth_failed = False
            auth_reason = ""

            if route_config.auth_required == "bearer":
                if not auth_header.startswith("Bearer "):
                    auth_failed = True
                    auth_reason = "Missing or invalid Bearer token"
            elif route_config.auth_required == "basic":
                if not auth_header.startswith("Basic "):
                    auth_failed = True
                    auth_reason = "Missing or invalid Basic authentication"
            else:
                # Generic auth requirement
                if not auth_header:
                    auth_failed = True
                    auth_reason = f"Missing {route_config.auth_required} authentication"

            if auth_failed:
                # Log suspicious activity for authentication failure
                await log_activity(
                    request,
                    self.logger,
                    log_type="suspicious",
                    reason=f"Authentication failure: {auth_reason}",
                    level=self.config.log_suspicious_level,
                    passive_mode=self.config.passive_mode,
                )

                # Send decorator violation event for authentication failure
                await self._send_middleware_event(
                    event_type="decorator_violation",
                    request=request,
                    action_taken="request_blocked"
                    if not self.config.passive_mode
                    else "logged_only",
                    reason=auth_reason,
                    decorator_type="authentication",
                    violation_type="require_auth",
                    auth_type=route_config.auth_required,
                )
                if not self.config.passive_mode:
                    return await self.create_error_response(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        default_message="Authentication required",
                    )

        # Route-specific referrer requirements
        if route_config and route_config.require_referrer:
            referrer = request.headers.get("referer", "")
            if not referrer:
                # Log suspicious activity for missing referrer
                await log_activity(
                    request,
                    self.logger,
                    log_type="suspicious",
                    reason="Missing referrer header",
                    level=self.config.log_suspicious_level,
                    passive_mode=self.config.passive_mode,
                )

                # Send decorator violation event for missing referrer
                await self._send_middleware_event(
                    event_type="decorator_violation",
                    request=request,
                    action_taken="request_blocked"
                    if not self.config.passive_mode
                    else "logged_only",
                    reason="Missing referrer header",
                    decorator_type="content_filtering",
                    violation_type="require_referrer",
                    allowed_domains=route_config.require_referrer,
                )
                if not self.config.passive_mode:
                    return await self.create_error_response(
                        status_code=status.HTTP_403_FORBIDDEN,
                        default_message="Referrer required",
                    )

            # Check if referrer domain is allowed
            referrer_allowed = False
            try:
                from urllib.parse import urlparse

                referrer_domain = urlparse(referrer).netloc.lower()
                for allowed_domain in route_config.require_referrer:
                    if (
                        referrer_domain == allowed_domain.lower()
                        or referrer_domain.endswith(f".{allowed_domain.lower()}")
                    ):
                        referrer_allowed = True
                        break
            except Exception:
                referrer_allowed = False

            if not referrer_allowed:
                # Log suspicious activity for invalid referrer
                await log_activity(
                    request,
                    self.logger,
                    log_type="suspicious",
                    reason=f"Invalid referrer: {referrer}",
                    level=self.config.log_suspicious_level,
                    passive_mode=self.config.passive_mode,
                )

                # Send decorator violation event for invalid referrer
                await self._send_middleware_event(
                    event_type="decorator_violation",
                    request=request,
                    action_taken="request_blocked"
                    if not self.config.passive_mode
                    else "logged_only",
                    reason=f"Referrer '{referrer}' not in allowed domains",
                    decorator_type="content_filtering",
                    violation_type="require_referrer",
                    referrer=referrer,
                    allowed_domains=route_config.require_referrer,
                )
                if not self.config.passive_mode:
                    return await self.create_error_response(
                        status_code=status.HTTP_403_FORBIDDEN,
                        default_message="Invalid referrer",
                    )

        # Route-specific custom validators
        if route_config and route_config.custom_validators:
            for validator in route_config.custom_validators:
                validation_response = await validator(request)
                if validation_response:
                    # Log suspicious activity for custom validation failure
                    await log_activity(
                        request,
                        self.logger,
                        log_type="suspicious",
                        reason="Custom validation failed",
                        level=self.config.log_suspicious_level,
                        passive_mode=self.config.passive_mode,
                    )

                    # Send decorator violation event for custom validation failure
                    await self._send_middleware_event(
                        event_type="decorator_violation",
                        request=request,
                        action_taken="request_blocked"
                        if not self.config.passive_mode
                        else "logged_only",
                        reason="Custom validation failed",
                        decorator_type="content_filtering",
                        violation_type="custom_validation",
                        validator_name=getattr(validator, "__name__", "anonymous"),
                    )
                    if not self.config.passive_mode and isinstance(
                        validation_response, Response
                    ):
                        return validation_response

        # Time window restrictions
        if route_config and route_config.time_restrictions:
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
                await self._send_middleware_event(
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
                    return await self.create_error_response(
                        status_code=status.HTTP_403_FORBIDDEN,
                        default_message="Access not allowed at this time",
                    )

        # Refresh cloud IP ranges
        if (
            self.config.block_cloud_providers
            and time.time() - self.last_cloud_ip_refresh > 3600
        ):
            await self.refresh_cloud_ip_ranges()

        # IP banning
        if not self._should_bypass_check(
            "ip_ban", route_config
        ) and await ip_ban_manager.is_ip_banned(client_ip):
            await log_activity(
                request,
                self.logger,
                log_type="suspicious",
                reason=f"Banned IP attempted access: {client_ip}",
                level=self.config.log_suspicious_level,
                passive_mode=self.config.passive_mode,
            )
            if not self.config.passive_mode:
                return await self.create_error_response(
                    status_code=status.HTTP_403_FORBIDDEN,
                    default_message="IP address banned",
                )

        # IP allowlist/blocklist (with route overrides)
        if not self._should_bypass_check("ip", route_config):
            # Check route-specific IP restrictions first
            if route_config:
                route_allowed = await self._check_route_ip_access(
                    client_ip, route_config
                )
                if route_allowed is not None and not route_allowed:
                    await log_activity(
                        request,
                        self.logger,
                        log_type="suspicious",
                        reason=f"IP not allowed by route config: {client_ip}",
                        level=self.config.log_suspicious_level,
                        passive_mode=self.config.passive_mode,
                    )
                    # Send decorator violation event to agent
                    await self._send_middleware_event(
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
                        return await self.create_error_response(
                            status_code=status.HTTP_403_FORBIDDEN,
                            default_message="Forbidden",
                        )
                # RouteConfig exists but == None, route doesn't specify IP rules
                # Skip global IP checks
            else:
                # Global IP check
                if not await is_ip_allowed(client_ip, self.config, self.geo_ip_handler):
                    await log_activity(
                        request,
                        self.logger,
                        log_type="suspicious",
                        reason=f"IP not allowed: {client_ip}",
                        level=self.config.log_suspicious_level,
                        passive_mode=self.config.passive_mode,
                    )
                    # Send global IP filtering event to agent
                    await self._send_middleware_event(
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
                        return await self.create_error_response(
                            status_code=status.HTTP_403_FORBIDDEN,
                            default_message="Forbidden",
                        )

        # Cloud providers (with route overrides)
        if not self._should_bypass_check("clouds", route_config):
            cloud_providers_to_check = None
            if route_config and route_config.block_cloud_providers:
                cloud_providers_to_check = route_config.block_cloud_providers
            elif self.config.block_cloud_providers:
                cloud_providers_to_check = self.config.block_cloud_providers

            if cloud_providers_to_check and cloud_handler.is_cloud_ip(
                client_ip, cloud_providers_to_check
            ):
                await log_activity(
                    request,
                    self.logger,
                    log_type="suspicious",
                    reason=f"Blocked cloud provider IP: {client_ip}",
                    level=self.config.log_suspicious_level,
                    passive_mode=self.config.passive_mode,
                )
                cloud_details = cloud_handler.get_cloud_provider_details(
                    client_ip, cloud_providers_to_check
                )
                if cloud_details and cloud_handler.agent_handler:
                    provider, network = cloud_details
                    await cloud_handler.send_cloud_detection_event(
                        client_ip,
                        provider,
                        network,
                        "request_blocked"
                        if not self.config.passive_mode
                        else "logged_only",
                    )

                # Send decorator violation event only for route-specific blocks
                if route_config and route_config.block_cloud_providers:
                    # Route-specific cloud provider block
                    await self._send_middleware_event(
                        event_type="decorator_violation",
                        request=request,
                        action_taken="request_blocked"
                        if not self.config.passive_mode
                        else "logged_only",
                        reason=f"Cloud provider IP {client_ip} blocked",
                        decorator_type="access_control",
                        violation_type="cloud_provider",
                        blocked_providers=list(cloud_providers_to_check),
                    )

                if not self.config.passive_mode:
                    return await self.create_error_response(
                        status_code=status.HTTP_403_FORBIDDEN,
                        default_message="Cloud provider IP not allowed",
                    )

        # User agent
        user_agent = request.headers.get("User-Agent", "")
        if not await self._check_user_agent_allowed(user_agent, route_config):
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
                await self._send_middleware_event(
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
                await self._send_middleware_event(
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
                return await self.create_error_response(
                    status_code=status.HTTP_403_FORBIDDEN,
                    default_message="User-Agent not allowed",
                )

        # Rate limit (with route overrides)
        if not self._should_bypass_check("rate_limit", route_config):
            rate_limit_response = await self._check_rate_limit(
                request, client_ip, route_config
            )
            if rate_limit_response:
                return rate_limit_response

        # Sus Activity
        penetration_enabled = self.config.enable_penetration_detection
        route_specific_detection = None
        if route_config and hasattr(route_config, "enable_suspicious_detection"):
            route_specific_detection = route_config.enable_suspicious_detection
            penetration_enabled = route_specific_detection

        if penetration_enabled and not self._should_bypass_check(
            "penetration", route_config
        ):
            detection_result, trigger_info = await detect_penetration_attempt(request)
        elif (
            route_specific_detection is False
            and self.config.enable_penetration_detection
        ):
            # Suspicious detection was disabled by decorator
            await self._send_middleware_event(
                event_type="decorator_violation",
                request=request,
                action_taken="detection_disabled",
                reason="Suspicious pattern detection disabled by route decorator",
                decorator_type="advanced",
                violation_type="suspicious_detection_disabled",
            )
            detection_result = False
            trigger_info = "disabled_by_decorator"
        else:
            detection_result = False
            trigger_info = "not_enabled"

        if detection_result:
            sus_specs = f"{client_ip} - {trigger_info}"
            self.suspicious_request_counts[client_ip] = (
                self.suspicious_request_counts.get(client_ip, 0) + 1
            )

            # Passive mode: just log, no blocking
            if self.config.passive_mode:
                await log_activity(
                    request,
                    self.logger,
                    log_type="suspicious",
                    reason=f"Suspicious activity detected: {client_ip}",
                    passive_mode=True,
                    trigger_info=trigger_info,
                    level=self.config.log_suspicious_level,
                )

                message = "Suspicious pattern detected (passive mode)"

                # Send passive mode detection event
                await self._send_middleware_event(
                    event_type="suspicious_request",
                    request=request,
                    action_taken="logged_only",
                    reason=f"{message}: {trigger_info}",
                    request_count=self.suspicious_request_counts[client_ip],
                    passive_mode=True,
                    trigger_info=trigger_info,
                )
                # Continue processing the request in passive mode
                # Don't return here, let the request continue
            # Active mode: block and ban
            else:
                # Check banning
                if (
                    self.config.enable_ip_banning
                    and self.suspicious_request_counts[client_ip]
                    >= self.config.auto_ban_threshold
                ):
                    await ip_ban_manager.ban_ip(
                        client_ip,
                        self.config.auto_ban_duration,
                        "penetration_attempt",
                    )
                    await log_activity(
                        request,
                        self.logger,
                        log_type="suspicious",
                        reason=f"IP banned due to suspicious activity: {sus_specs}",
                        level=self.config.log_suspicious_level,
                    )

                    return await self.create_error_response(
                        status_code=status.HTTP_403_FORBIDDEN,
                        default_message="IP has been banned",
                    )

                await log_activity(
                    request,
                    self.logger,
                    log_type="suspicious",
                    reason=f"Suspicious activity detected for IP: {sus_specs}",
                    level=self.config.log_suspicious_level,
                )

                return await self.create_error_response(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    default_message="Suspicious activity detected",
                )

        # Custom request
        if self.config.custom_request_check:
            custom_response = await self.config.custom_request_check(request)
            if custom_response:
                # Send custom request check event
                await self._send_middleware_event(
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
                    if self.config.custom_response_modifier:
                        modified_response = await self.config.custom_response_modifier(
                            custom_response
                        )
                        return modified_response
                    return custom_response

        # Process behavioral rules before calling next
        if route_config and route_config.behavior_rules:
            await self._process_decorator_usage_rules(request, client_ip, route_config)

        # Call next
        start_time = time.time()
        response = await call_next(request)
        end_time = time.time()
        response_time = end_time - start_time

        # Process behavioral rules after response
        if route_config and route_config.behavior_rules:
            await self._process_decorator_return_rules(
                request, response, client_ip, route_config
            )

        await self._collect_request_metrics(
            request, response_time, response.status_code
        )

        # Add security headers if enabled
        if self.config.security_headers and self.config.security_headers.get(
            "enabled", True
        ):
            security_headers = await security_headers_manager.get_headers(
                str(request.url.path)
            )
            for header_name, header_value in security_headers.items():
                response.headers[header_name] = header_value

            # Add CORS headers if origin is present
            origin = request.headers.get("origin")
            if origin:
                cors_headers = await security_headers_manager.get_cors_headers(origin)
                for header_name, header_value in cors_headers.items():
                    response.headers[header_name] = header_value

        if self.config.custom_response_modifier:
            modified_response = await self.config.custom_response_modifier(response)
            return modified_response

        return response

    def _get_route_decorator_config(self, request: Request) -> RouteConfig | None:
        """Get route-specific security configuration from decorators."""
        app = request.scope.get("app")

        guard_decorator: BaseSecurityDecorator | None = None
        if app and hasattr(app, "state") and hasattr(app.state, "guard_decorator"):
            app_guard_decorator = app.state.guard_decorator
            if isinstance(app_guard_decorator, BaseSecurityDecorator):
                guard_decorator = app_guard_decorator
        elif self.guard_decorator:
            guard_decorator = self.guard_decorator

        if not guard_decorator:
            return None

        path = request.url.path
        method = request.method

        if app:
            for route in app.routes:
                if (
                    hasattr(route, "path")
                    and hasattr(route, "methods")
                    and route.path == path
                    and method in route.methods
                    and hasattr(route, "endpoint")
                    and hasattr(route.endpoint, "_guard_route_id")
                ):
                    route_id = route.endpoint._guard_route_id
                    return guard_decorator.get_route_config(route_id)

        return None

    def _should_bypass_check(
        self, check_name: str, route_config: RouteConfig | None
    ) -> bool:
        """Check if a security check should be bypassed."""
        if not route_config:
            return False
        return (
            check_name in route_config.bypassed_checks
            or "all" in route_config.bypassed_checks
        )

    async def _check_route_ip_access(
        self, client_ip: str, route_config: RouteConfig
    ) -> bool | None:
        """
        Check route-specific IP access rules. Returns None if no route rules apply.
        """
        try:
            ip_addr = ip_address(client_ip)

            # Route blacklist
            if route_config.ip_blacklist:
                for blocked in route_config.ip_blacklist:
                    if "/" in blocked:
                        if ip_addr in ip_network(blocked, strict=False):
                            return False
                    elif client_ip == blocked:
                        return False

            # Route whitelist
            if route_config.ip_whitelist:
                for allowed in route_config.ip_whitelist:
                    if "/" in allowed:
                        if ip_addr in ip_network(allowed, strict=False):
                            return True
                    elif client_ip == allowed:
                        return True
                return False  # If whitelist exists but IP not in it

            # Route countries
            if route_config.blocked_countries and self.geo_ip_handler:
                country = self.geo_ip_handler.get_country(client_ip)
                if country and country in route_config.blocked_countries:
                    return False

            if route_config.whitelist_countries and self.geo_ip_handler:
                country = self.geo_ip_handler.get_country(client_ip)
                if country:
                    return country in route_config.whitelist_countries
                else:
                    return False

            return None  # No route-specific rules, fall back to global
        except ValueError:
            return False

    async def _check_user_agent_allowed(
        self, user_agent: str, route_config: RouteConfig | None
    ) -> bool:
        """Check user agent against both route and global rules."""
        # Check route-specific blocked user agents first
        if route_config and route_config.blocked_user_agents:
            for pattern in route_config.blocked_user_agents:
                if re.search(pattern, user_agent, re.IGNORECASE):
                    return False

        # Fall back to global check
        return await is_user_agent_allowed(user_agent, self.config)

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

    async def _check_rate_limit(
        self, request: Request, client_ip: str, route_config: RouteConfig | None
    ) -> Response | None:
        """
        Check rate limiting with route overrides and dynamic endpoint-specific config.
        """

        # Dynamic Rules Rate Limit (agent feature)
        endpoint_path = request.url.path
        if endpoint_path in self.config.endpoint_rate_limits:
            rate_limit, window = self.config.endpoint_rate_limits[endpoint_path]
            endpoint_rate_config = SecurityConfig(
                rate_limit=rate_limit,
                rate_limit_window=window,
                enable_redis=self.config.enable_redis,
                redis_url=self.config.redis_url,
                redis_prefix=self.config.redis_prefix,
            )
            endpoint_rate_handler = RateLimitManager(endpoint_rate_config)
            if self.redis_handler:
                await endpoint_rate_handler.initialize_redis(self.redis_handler)

            # Check
            response = await endpoint_rate_handler.check_rate_limit(
                request, client_ip, self.create_error_response
            )

            # If rate limit exceeded, send endpoint-specific event
            if response is not None:
                message = "Endpoint-specific rate limit exceeded"
                details = f"{rate_limit} requests per {window}s for {endpoint_path}"

                await self._send_middleware_event(
                    event_type="dynamic_rule_violation",
                    request=request,
                    action_taken="request_blocked"
                    if not self.config.passive_mode
                    else "logged_only",
                    reason=f"{message}: {details}",
                    rule_type="endpoint_rate_limit",
                    endpoint=endpoint_path,
                    rate_limit=rate_limit,
                    window=window,
                )

                if self.config.passive_mode:
                    return None  # Don't block in passive mode

            return response

        # Use route-specific rate limit if available
        if route_config and route_config.rate_limit is not None:
            route_rate_config = SecurityConfig(
                rate_limit=route_config.rate_limit,
                rate_limit_window=route_config.rate_limit_window or 60,
                enable_redis=self.config.enable_redis,
                redis_url=self.config.redis_url,
                redis_prefix=self.config.redis_prefix,
            )
            route_rate_handler = RateLimitManager(route_rate_config)
            if self.redis_handler:
                await route_rate_handler.initialize_redis(self.redis_handler)

            # Check rate limit
            response = await route_rate_handler.check_rate_limit(
                request, client_ip, self.create_error_response
            )

            # If rate limit exceeded, send decorator-specific event
            if response is not None:
                message = "Route-specific rate limit exceeded"
                details = (
                    f"{route_config.rate_limit} requests per "
                    f"{self.config.rate_limit_window or 60}s"
                )
                await self._send_middleware_event(
                    event_type="decorator_violation",
                    request=request,
                    action_taken="request_blocked"
                    if not self.config.passive_mode
                    else "logged_only",
                    reason=f"{message}: {details}",
                    decorator_type="rate_limiting",
                    violation_type="rate_limit",
                    rate_limit=route_config.rate_limit,
                    window=route_config.rate_limit_window or 60,
                )

                if self.config.passive_mode:
                    return None  # Don't block in passive mode

            return response

        # Fall back to global rate limiting
        response = await self.rate_limit_handler.check_rate_limit(
            request, client_ip, self.create_error_response
        )

        if response is not None and self.config.passive_mode:
            # In passive mode, don't block even if rate limit exceeded
            return None

        return response

    async def _process_decorator_usage_rules(
        self, request: Request, client_ip: str, route_config: RouteConfig
    ) -> None:
        """Process behavioral usage rules from decorators before request processing."""
        if not self.guard_decorator:
            return

        endpoint_id = self._get_endpoint_id(request)
        for rule in route_config.behavior_rules:
            if rule.rule_type in ["usage", "frequency"]:
                threshold_exceeded = (
                    await self.guard_decorator.behavior_tracker.track_endpoint_usage(
                        endpoint_id, client_ip, rule
                    )
                )
                if threshold_exceeded:
                    details = f"{rule.threshold} calls in {rule.window}s"
                    message = f"Behavioral {rule.rule_type}"
                    reason = "threshold exceeded"

                    # Send decorator violation event for behavioral rule violation
                    await self._send_middleware_event(
                        event_type="decorator_violation",
                        request=request,
                        action_taken="behavioral_action_triggered",
                        reason=f"{message} {reason}: {details}",
                        decorator_type="behavioral",
                        violation_type=rule.rule_type,
                        threshold=rule.threshold,
                        window=rule.window,
                        action=rule.action,
                        endpoint_id=endpoint_id,
                    )

                    await self.guard_decorator.behavior_tracker.apply_action(
                        rule,
                        client_ip,
                        endpoint_id,
                        f"Usage threshold exceeded: {details}",
                    )

    async def _process_decorator_return_rules(
        self,
        request: Request,
        response: Response,
        client_ip: str,
        route_config: RouteConfig,
    ) -> None:
        """Process behavioral return pattern rules from decorators after response."""
        if not self.guard_decorator:
            return

        endpoint_id = self._get_endpoint_id(request)
        for rule in route_config.behavior_rules:
            if rule.rule_type == "return_pattern":
                pattern_detected = (
                    await self.guard_decorator.behavior_tracker.track_return_pattern(
                        endpoint_id, client_ip, response, rule
                    )
                )
                if pattern_detected:
                    details = f"{rule.threshold} for '{rule.pattern}' in {rule.window}s"

                    # Send decorator violation event for return pattern violation
                    await self._send_middleware_event(
                        event_type="decorator_violation",
                        request=request,
                        action_taken="behavioral_action_triggered",
                        reason=f"Return pattern threshold exceeded: {details}",
                        decorator_type="behavioral",
                        violation_type="return_pattern",
                        threshold=rule.threshold,
                        window=rule.window,
                        pattern=rule.pattern,
                        action=rule.action,
                        endpoint_id=endpoint_id,
                    )

                    await self.guard_decorator.behavior_tracker.apply_action(
                        rule,
                        client_ip,
                        endpoint_id,
                        f"Return pattern threshold exceeded: {details}",
                    )

    def _get_endpoint_id(self, request: Request) -> str:
        """Generate unique endpoint identifier."""
        if hasattr(request, "scope") and "route" in request.scope:
            route = request.scope["route"]
            if hasattr(route, "endpoint"):
                return f"{route.endpoint.__module__}.{route.endpoint.__qualname__}"
        return f"{request.method}:{request.url.path}"

    async def refresh_cloud_ip_ranges(self) -> None:
        """Refresh cloud IP ranges asynchronously."""
        if not self.config.block_cloud_providers:
            return

        if self.config.enable_redis and self.redis_handler:
            await cloud_handler.refresh_async(self.config.block_cloud_providers)
        else:
            cloud_handler.refresh(self.config.block_cloud_providers)
        self.last_cloud_ip_refresh = int(time.time())

    async def create_error_response(
        self, status_code: int, default_message: str
    ) -> Response:
        """
        Create an error response with a custom message.
        """
        custom_message = self.config.custom_error_responses.get(
            status_code, default_message
        )
        response = Response(custom_message, status_code=status_code)

        # Add security headers to error responses
        if self.config.security_headers and self.config.security_headers.get(
            "enabled", True
        ):
            security_headers = await security_headers_manager.get_headers()
            for header_name, header_value in security_headers.items():
                response.headers[header_name] = header_value

        if self.config.custom_response_modifier:
            response = await self.config.custom_response_modifier(response)

        return response

    async def reset(self) -> None:
        """Reset rate limiting state."""
        await self.rate_limit_handler.reset()

    @staticmethod
    def configure_cors(app: FastAPI, config: SecurityConfig) -> bool:
        """
        Configure FastAPI's CORS middleware
        based on SecurityConfig.
        """
        if config.enable_cors:
            cors_params: dict[str, Any] = {
                "allow_origins": config.cors_allow_origins,
                "allow_methods": config.cors_allow_methods,
                "allow_headers": config.cors_allow_headers,
                "allow_credentials": config.cors_allow_credentials,
                "max_age": config.cors_max_age,
            }

            if config.cors_expose_headers:
                cors_params["expose_headers"] = config.cors_expose_headers

            app.add_middleware(CORSMiddleware, **cors_params)
            return True
        return False

    async def initialize(self) -> None:
        """Initialize all components asynchronously"""
        if self.config.enable_redis and self.redis_handler:
            await self.redis_handler.initialize()
            if self.config.block_cloud_providers:
                await cloud_handler.initialize_redis(
                    self.redis_handler, self.config.block_cloud_providers
                )
            await ip_ban_manager.initialize_redis(self.redis_handler)
            if self.geo_ip_handler is not None:
                await self.geo_ip_handler.initialize_redis(self.redis_handler)
            await self.rate_limit_handler.initialize_redis(self.redis_handler)
            await sus_patterns_handler.initialize_redis(self.redis_handler)

        # Initialize agent handler
        if self.agent_handler:
            await self.agent_handler.start()
            # Connect agent to Redis if available
            if self.redis_handler:
                await self.agent_handler.initialize_redis(self.redis_handler)
                # Initialize agent in Redis handler
                await self.redis_handler.initialize_agent(self.agent_handler)

            # Initialize agent in all handlers
            await ip_ban_manager.initialize_agent(self.agent_handler)
            await self.rate_limit_handler.initialize_agent(self.agent_handler)
            await sus_patterns_handler.initialize_agent(self.agent_handler)
            if self.config.block_cloud_providers:
                await cloud_handler.initialize_agent(self.agent_handler)
            if self.geo_ip_handler and hasattr(self.geo_ip_handler, "initialize_agent"):
                await self.geo_ip_handler.initialize_agent(self.agent_handler)

            # Initialize agent in decorator handler if it exists
            if self.guard_decorator and hasattr(
                self.guard_decorator, "initialize_agent"
            ):
                await self.guard_decorator.initialize_agent(self.agent_handler)

            # Initialize dynamic rule manager if enabled
            if self.config.enable_dynamic_rules:
                from guard.handlers.dynamic_rule_handler import DynamicRuleManager

                dynamic_rule_manager = DynamicRuleManager(self.config)
                await dynamic_rule_manager.initialize_agent(self.agent_handler)
                if self.redis_handler:
                    await dynamic_rule_manager.initialize_redis(self.redis_handler)
