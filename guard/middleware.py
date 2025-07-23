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
        self.logger = logging.getLogger(__name__)
        self.last_cloud_ip_refresh = 0
        self.suspicious_request_counts: dict[str, int] = {}
        self.last_cleanup = time.time()
        self.rate_limit_handler = RateLimitManager(config)
        self.guard_decorator: BaseSecurityDecorator | None = None

        self.geo_ip_handler = None
        if config.whitelist_countries or config.blocked_countries:
            self.geo_ip_handler = config.geo_ip_handler

        # Initialize Redis handler if enabled
        self.redis_handler = None
        if config.enable_redis:
            from guard.handlers.redis_handler import RedisManager

            self.redis_handler = RedisManager(config)

    async def setup_logger(self) -> None:
        self.logger = await setup_custom_logging("security.log")

    def set_decorator_handler(
        self, decorator_handler: BaseSecurityDecorator | None
    ) -> None:
        """Set the SecurityDecorator instance for decorator support."""
        self.guard_decorator = decorator_handler

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
        client_ip = extract_client_ip(request, self.config)

        # Excluded paths
        if any(request.url.path.startswith(path) for path in self.config.exclude_paths):
            response = await call_next(request)
            if self.config.custom_response_modifier:
                modified_response = await self.config.custom_response_modifier(response)
                return modified_response
            return response

        # Check if security checks should be bypassed
        if route_config and self._should_bypass_check("all", route_config):
            response = await call_next(request)
            if self.config.custom_response_modifier:
                modified_response = await self.config.custom_response_modifier(response)
                return modified_response
            return response

        # Log request
        await log_activity(request, self.logger, level=self.config.log_request_level)

        # Route-specific request size check
        if route_config and route_config.max_request_size:
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > route_config.max_request_size:
                return await self.create_error_response(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    default_message="Request too large",
                )

        # Route-specific content type check
        if route_config and route_config.allowed_content_types:
            content_type = request.headers.get("content-type", "").split(";")[0]
            if content_type not in route_config.allowed_content_types:
                return await self.create_error_response(
                    status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                    default_message="Unsupported content type",
                )

        # Route-specific header requirements
        if route_config and route_config.required_headers:
            for header, expected in route_config.required_headers.items():
                if expected == "required" and not request.headers.get(header):
                    return await self.create_error_response(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        default_message=f"Missing required header: {header}",
                    )

        # Route-specific custom validators
        if route_config and route_config.custom_validators:
            for validator in route_config.custom_validators:
                validation_response = await validator(request)
                if validation_response:
                    if isinstance(validation_response, Response):
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
                )
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
            )
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
                    )
                    return await self.create_error_response(
                        status_code=status.HTTP_403_FORBIDDEN,
                        default_message="Forbidden",
                    )
                # TODO: Review this.
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
                    )
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
                )
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
            )
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
        if route_config and hasattr(route_config, "enable_suspicious_detection"):
            penetration_enabled = route_config.enable_suspicious_detection

        if penetration_enabled and not self._should_bypass_check(
            "penetration", route_config
        ):
            detection_result, trigger_info = await detect_penetration_attempt(
                request, self.config.regex_timeout
            )
            sus_specs = f"{client_ip} - {trigger_info}"
            if detection_result:
                self.suspicious_request_counts[client_ip] = (
                    self.suspicious_request_counts.get(client_ip, 0) + 1
                )

                # Block and Ban
                if not self.config.passive_mode:
                    # Check banning
                    if (
                        self.config.enable_ip_banning
                        and self.suspicious_request_counts[client_ip]
                        >= self.config.auto_ban_threshold
                    ):
                        await ip_ban_manager.ban_ip(
                            client_ip, self.config.auto_ban_duration
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
                # Passive mode: just log, no blocking
                else:
                    await log_activity(
                        request,
                        self.logger,
                        log_type="suspicious",
                        reason=f"Suspicious activity detected: {client_ip}",
                        passive_mode=True,
                        trigger_info=trigger_info,
                        level=self.config.log_suspicious_level,
                    )

        # Custom request
        if self.config.custom_request_check:
            custom_response = await self.config.custom_request_check(request)
            if custom_response:
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
        response = await call_next(request)

        # Process behavioral rules after response
        if route_config and route_config.behavior_rules:
            await self._process_decorator_return_rules(
                request, response, client_ip, route_config
            )

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

            if route_config.allowed_countries and self.geo_ip_handler:
                country = self.geo_ip_handler.get_country(client_ip)
                if country:
                    return country in route_config.allowed_countries
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
        """Check rate limiting with route overrides."""
        # Use route-specific rate limit if available
        if route_config and route_config.rate_limit is not None:
            # Create temporary config for route-specific rate limiting
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

            return await route_rate_handler.check_rate_limit(
                request, client_ip, self.create_error_response
            )

        # Fall back to global rate limiting
        return await self.rate_limit_handler.check_rate_limit(
            request, client_ip, self.create_error_response
        )

    async def _process_decorator_usage_rules(
        self, request: Request, client_ip: str, route_config: RouteConfig
    ) -> None:
        """Process behavioral usage rules from decorators before request processing."""
        if not self.guard_decorator:
            return

        endpoint_id = self._get_endpoint_id(request)
        for rule in route_config.behavior_rules:
            if rule.rule_type == "usage":
                threshold_exceeded = (
                    await self.guard_decorator.behavior_tracker.track_endpoint_usage(
                        endpoint_id, client_ip, rule
                    )
                )
                if threshold_exceeded:
                    details = f"{rule.threshold} calls in {rule.window}s"
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
